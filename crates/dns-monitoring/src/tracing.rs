//! Distributed tracing integration using OpenTelemetry
//!
//! Provides comprehensive tracing for DNS queries and system operations
//! with support for multiple exporters and sampling strategies.

use dns_core::{DnsResult, DnsError};
use opentelemetry::{
    global, trace::{TraceError, Tracer, TracerProvider}, KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    trace::{self, RandomIdGenerator, Sampler},
    Resource,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{Level, Subscriber};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry,
};

/// Configuration for distributed tracing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub enabled: bool,
    /// Service name for tracing
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Environment (e.g., "production", "staging", "development")
    pub environment: String,
    /// OTLP exporter configuration
    pub otlp: OtlpConfig,
    /// Sampling configuration
    pub sampling: SamplingConfig,
    /// Additional resource attributes
    pub resource_attributes: HashMap<String, String>,
    /// Enable console output
    pub console_output: bool,
    /// Log level for console output
    pub console_level: String,
}

/// OTLP exporter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpConfig {
    /// OTLP endpoint URL
    pub endpoint: String,
    /// Timeout for exports in seconds
    pub timeout_secs: u64,
    /// Headers to include with exports
    pub headers: HashMap<String, String>,
    /// Enable TLS
    pub tls_enabled: bool,
    /// Batch export configuration
    pub batch: BatchConfig,
}

/// Batch export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Maximum batch size
    pub max_export_batch_size: usize,
    /// Export timeout in milliseconds
    pub export_timeout_millis: u64,
    /// Maximum queue size
    pub max_queue_size: usize,
    /// Schedule delay in milliseconds
    pub schedule_delay_millis: u64,
}

/// Sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sampling strategy
    pub strategy: SamplingStrategy,
    /// Sampling rate (0.0 to 1.0)
    pub rate: f64,
    /// Enable parent-based sampling
    pub parent_based: bool,
}

/// Sampling strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SamplingStrategy {
    /// Always sample
    AlwaysOn,
    /// Never sample
    AlwaysOff,
    /// Sample based on trace ID
    TraceIdRatio,
    /// Parent-based sampling
    ParentBased,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "dns-server".to_string(),
            service_version: "0.1.0".to_string(),
            environment: "development".to_string(),
            otlp: OtlpConfig {
                endpoint: "http://localhost:4317".to_string(),
                timeout_secs: 10,
                headers: HashMap::new(),
                tls_enabled: false,
                batch: BatchConfig {
                    max_export_batch_size: 512,
                    export_timeout_millis: 30000,
                    max_queue_size: 2048,
                    schedule_delay_millis: 5000,
                },
            },
            sampling: SamplingConfig {
                strategy: SamplingStrategy::TraceIdRatio,
                rate: 0.1, // Sample 10% of traces by default
                parent_based: true,
            },
            resource_attributes: HashMap::new(),
            console_output: true,
            console_level: "info".to_string(),
        }
    }
}

/// Tracing manager for OpenTelemetry integration
pub struct TracingManager {
    config: TracingConfig,
    tracer: Option<Box<dyn Tracer + Send + Sync>>,
}

impl TracingManager {
    /// Create a new tracing manager
    pub async fn new(config: TracingConfig) -> DnsResult<Self> {
        Ok(Self {
            config,
            tracer: None,
        })
    }
    
    /// Initialize the tracing system
    pub async fn initialize(&mut self) -> DnsResult<()> {
        if !self.config.enabled {
            // Initialize basic console logging only
            self.init_console_only()?;
            return Ok(());
        }
        
        // Initialize OpenTelemetry tracer
        let tracer = self.init_opentelemetry().await?;
        self.tracer = Some(tracer);
        
        // Initialize tracing subscriber with OpenTelemetry layer
        self.init_subscriber().await?;
        
        tracing::info!(
            service_name = %self.config.service_name,
            service_version = %self.config.service_version,
            environment = %self.config.environment,
            "Distributed tracing initialized"
        );
        
        Ok(())
    }
    
    /// Initialize OpenTelemetry tracer
    async fn init_opentelemetry(&self) -> DnsResult<Box<dyn Tracer + Send + Sync>> {
        // Create resource with service information
        let mut resource_kvs = vec![
            KeyValue::new("service.name", self.config.service_name.clone()),
            KeyValue::new("service.version", self.config.service_version.clone()),
            KeyValue::new("service.environment", self.config.environment.clone()),
        ];
        
        // Add custom resource attributes
        for (key, value) in &self.config.resource_attributes {
            resource_kvs.push(KeyValue::new(key.clone(), value.clone()));
        }
        
        let resource = Resource::new(resource_kvs);
        
        // Create sampler based on configuration
        let sampler = match self.config.sampling.strategy {
            SamplingStrategy::AlwaysOn => Sampler::AlwaysOn,
            SamplingStrategy::AlwaysOff => Sampler::AlwaysOff,
            SamplingStrategy::TraceIdRatio => Sampler::TraceIdRatioBased(self.config.sampling.rate),
            SamplingStrategy::ParentBased => {
                if self.config.sampling.parent_based {
                    Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(self.config.sampling.rate)))
                } else {
                    Sampler::TraceIdRatioBased(self.config.sampling.rate)
                }
            }
        };
        
        // Create OTLP exporter
        let mut exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(&self.config.otlp.endpoint)
            .with_timeout(Duration::from_secs(self.config.otlp.timeout_secs));
        
        // Add headers if configured
        if !self.config.otlp.headers.is_empty() {
            let mut metadata = tonic::metadata::MetadataMap::new();
            for (key, value) in &self.config.otlp.headers {
                if let (Ok(key), Ok(value)) = (
                    tonic::metadata::MetadataKey::from_bytes(key.as_bytes()),
                    tonic::metadata::MetadataValue::try_from(value)
                ) {
                    metadata.insert(key, value);
                }
            }
            exporter = exporter.with_metadata(metadata);
        }
        
        // Create trace provider
        let provider = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_sampler(sampler)
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource)
            .with_batch_exporter(
                exporter,
                opentelemetry_sdk::trace::BatchConfig::default()
                    .with_max_export_batch_size(self.config.otlp.batch.max_export_batch_size)
                    .with_export_timeout(Duration::from_millis(self.config.otlp.batch.export_timeout_millis))
                    .with_max_queue_size(self.config.otlp.batch.max_queue_size)
                    .with_scheduled_delay(Duration::from_millis(self.config.otlp.batch.schedule_delay_millis)),
            )
            .build();
        
        // Set global tracer provider
        global::set_tracer_provider(provider.clone());
        
        // Get tracer
        let tracer = provider.tracer("dns-server");
        
        Ok(Box::new(tracer))
    }
    
    /// Initialize tracing subscriber with OpenTelemetry layer
    async fn init_subscriber(&self) -> DnsResult<()> {
        let telemetry_layer = tracing_opentelemetry::layer()
            .with_tracer(global::tracer("dns-server"));
        
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&self.config.console_level));
        
        if self.config.console_output {
            // Initialize with both console and OpenTelemetry layers
            Registry::default()
                .with(env_filter)
                .with(fmt::layer().with_target(false))
                .with(telemetry_layer)
                .try_init()
                .map_err(|e| DnsError::ConfigError(format!("Failed to initialize tracing subscriber: {}", e)))?;
        } else {
            // Initialize with OpenTelemetry layer only
            Registry::default()
                .with(env_filter)
                .with(telemetry_layer)
                .try_init()
                .map_err(|e| DnsError::ConfigError(format!("Failed to initialize tracing subscriber: {}", e)))?;
        }
        
        Ok(())
    }
    
    /// Initialize console-only logging (when OpenTelemetry is disabled)
    fn init_console_only(&self) -> DnsResult<()> {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&self.config.console_level));
        
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .try_init()
            .map_err(|e| DnsError::ConfigError(format!("Failed to initialize console logging: {}", e)))?;
        
        Ok(())
    }
    
    /// Shutdown the tracing system
    pub async fn shutdown(&self) -> DnsResult<()> {
        if self.config.enabled {
            global::shutdown_tracer_provider();
            tracing::info!("Distributed tracing shutdown complete");
        }
        Ok(())
    }
    
    /// Get the tracer instance
    pub fn tracer(&self) -> Option<&dyn Tracer> {
        self.tracer.as_ref().map(|t| t.as_ref())
    }
    
    /// Create a span for DNS query processing
    pub fn create_query_span(&self, query_name: &str, query_type: &str, client_ip: &str) -> tracing::Span {
        tracing::info_span!(
            "dns_query",
            query.name = query_name,
            query.type = query_type,
            client.ip = client_ip,
            otel.kind = "server",
            otel.name = "dns_query_processing"
        )
    }
    
    /// Create a span for cache operations
    pub fn create_cache_span(&self, operation: &str, key: &str) -> tracing::Span {
        tracing::debug_span!(
            "cache_operation",
            cache.operation = operation,
            cache.key = key,
            otel.kind = "internal",
            otel.name = format!("cache_{}", operation).as_str()
        )
    }
    
    /// Create a span for storage operations
    pub fn create_storage_span(&self, operation: &str, zone: &str) -> tracing::Span {
        tracing::debug_span!(
            "storage_operation",
            storage.operation = operation,
            storage.zone = zone,
            otel.kind = "internal",
            otel.name = format!("storage_{}", operation).as_str()
        )
    }
    
    /// Create a span for cluster operations
    pub fn create_cluster_span(&self, operation: &str, node_id: &str) -> tracing::Span {
        tracing::debug_span!(
            "cluster_operation",
            cluster.operation = operation,
            cluster.node_id = node_id,
            otel.kind = "client",
            otel.name = format!("cluster_{}", operation).as_str()
        )
    }
    
    /// Create a span for security operations
    pub fn create_security_span(&self, operation: &str, rule_type: &str) -> tracing::Span {
        tracing::debug_span!(
            "security_operation",
            security.operation = operation,
            security.rule_type = rule_type,
            otel.kind = "internal",
            otel.name = format!("security_{}", operation).as_str()
        )
    }
    
    /// Add error information to current span
    pub fn record_error(&self, error: &dyn std::error::Error) {
        tracing::Span::current().record("error", true);
        tracing::Span::current().record("error.message", error.to_string().as_str());
        tracing::error!(error = %error, "Operation failed");
    }
    
    /// Add custom attributes to current span
    pub fn record_attributes(&self, attributes: &[(&str, &str)]) {
        let current_span = tracing::Span::current();
        for (key, value) in attributes {
            current_span.record(key, value);
        }
    }
    
    /// Check if tracing is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Convenience macros for creating traced operations
#[macro_export]
macro_rules! trace_dns_query {
    ($tracer:expr, $name:expr, $qtype:expr, $client:expr, $body:expr) => {
        {
            let span = $tracer.create_query_span($name, $qtype, $client);
            let _guard = span.enter();
            $body
        }
    };
}

#[macro_export]
macro_rules! trace_cache_operation {
    ($tracer:expr, $op:expr, $key:expr, $body:expr) => {
        {
            let span = $tracer.create_cache_span($op, $key);
            let _guard = span.enter();
            $body
        }
    };
}

#[macro_export]
macro_rules! trace_storage_operation {
    ($tracer:expr, $op:expr, $zone:expr, $body:expr) => {
        {
            let span = $tracer.create_storage_span($op, $zone);
            let _guard = span.enter();
            $body
        }
    };
}

/// Helper function to extract trace context from HTTP headers
pub fn extract_trace_context(headers: &hyper::HeaderMap) -> Option<opentelemetry::Context> {
    use opentelemetry::propagation::Extractor;
    
    struct HeaderExtractor<'a>(&'a hyper::HeaderMap);
    
    impl<'a> Extractor for HeaderExtractor<'a> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }
        
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|k| k.as_str()).collect()
        }
    }
    
    let extractor = HeaderExtractor(headers);
    let propagator = opentelemetry::global::get_text_map_propagator(|p| p.extract(&extractor));
    Some(propagator)
}

/// Helper function to inject trace context into HTTP headers
pub fn inject_trace_context(headers: &mut hyper::HeaderMap, context: &opentelemetry::Context) {
    use opentelemetry::propagation::Injector;
    
    struct HeaderInjector<'a>(&'a mut hyper::HeaderMap);
    
    impl<'a> Injector for HeaderInjector<'a> {
        fn set(&mut self, key: &str, value: String) {
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::from_bytes(key.as_bytes()),
                hyper::header::HeaderValue::from_str(&value)
            ) {
                self.0.insert(name, val);
            }
        }
    }
    
    let mut injector = HeaderInjector(headers);
    opentelemetry::global::get_text_map_propagator(|p| p.inject_context(context, &mut injector));
}