//! Alert management system for monitoring events
//!
//! Provides webhook notifications and alert management for critical
//! DNS server events and threshold violations.

use dns_core::{DnsResult, DnsError, global_metrics};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::interval;

/// Configuration for alert management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alert system
    pub enabled: bool,
    /// Alert check interval in seconds
    pub check_interval_secs: u64,
    /// Webhook configurations
    pub webhooks: Vec<WebhookConfig>,
    /// Alert rules
    pub rules: Vec<AlertRule>,
    /// Alert suppression settings
    pub suppression: SuppressionConfig,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook name
    pub name: String,
    /// Webhook URL
    pub url: String,
    /// HTTP method (GET, POST, PUT)
    pub method: String,
    /// Headers to include
    pub headers: HashMap<String, String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Retry configuration
    pub retry: RetryConfig,
    /// Alert levels to send to this webhook
    pub alert_levels: Vec<AlertLevel>,
}

/// Retry configuration for webhooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries
    pub max_retries: u32,
    /// Initial retry delay in seconds
    pub initial_delay_secs: u64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    /// Maximum retry delay in seconds
    pub max_delay_secs: u64,
}

/// Alert rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Alert level
    pub level: AlertLevel,
    /// Metric to monitor
    pub metric: String,
    /// Condition type
    pub condition: AlertCondition,
    /// Threshold value
    pub threshold: f64,
    /// Duration threshold must be exceeded (in seconds)
    pub duration_secs: u64,
    /// Enable this rule
    pub enabled: bool,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Alert levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertLevel {
    /// Informational alerts
    Info,
    /// Warning alerts
    Warning,
    /// Critical alerts
    Critical,
}

/// Alert conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    /// Greater than threshold
    GreaterThan,
    /// Less than threshold
    LessThan,
    /// Equal to threshold
    EqualTo,
    /// Not equal to threshold
    NotEqualTo,
    /// Greater than or equal to threshold
    GreaterThanOrEqual,
    /// Less than or equal to threshold
    LessThanOrEqual,
}

/// Alert suppression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionConfig {
    /// Enable alert suppression
    pub enabled: bool,
    /// Minimum time between identical alerts (in seconds)
    pub min_interval_secs: u64,
    /// Maximum number of alerts per rule per hour
    pub max_alerts_per_hour: u32,
    /// Suppress alerts during maintenance windows
    pub maintenance_windows: Vec<MaintenanceWindow>,
}

/// Maintenance window configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    /// Window name
    pub name: String,
    /// Start time (cron expression or timestamp)
    pub start: String,
    /// End time (cron expression or timestamp)
    pub end: String,
    /// Days of week (0=Sunday, 6=Saturday)
    pub days_of_week: Vec<u8>,
    /// Timezone
    pub timezone: String,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default
            check_interval_secs: 60,
            webhooks: vec![],
            rules: Self::default_rules(),
            suppression: SuppressionConfig {
                enabled: true,
                min_interval_secs: 300, // 5 minutes
                max_alerts_per_hour: 10,
                maintenance_windows: vec![],
            },
        }
    }
}

impl AlertConfig {
    /// Create default alert rules
    fn default_rules() -> Vec<AlertRule> {
        vec![
            AlertRule {
                name: "high_error_rate".to_string(),
                description: "High DNS query error rate detected".to_string(),
                level: AlertLevel::Critical,
                metric: "error_rate_percent".to_string(),
                condition: AlertCondition::GreaterThan,
                threshold: 5.0,
                duration_secs: 300,
                enabled: true,
                metadata: HashMap::new(),
            },
            AlertRule {
                name: "low_cache_hit_rate".to_string(),
                description: "Low cache hit rate detected".to_string(),
                level: AlertLevel::Warning,
                metric: "cache_hit_rate_percent".to_string(),
                condition: AlertCondition::LessThan,
                threshold: 80.0,
                duration_secs: 600,
                enabled: true,
                metadata: HashMap::new(),
            },
            AlertRule {
                name: "high_response_time".to_string(),
                description: "High DNS response time detected".to_string(),
                level: AlertLevel::Warning,
                metric: "avg_response_time_ms".to_string(),
                condition: AlertCondition::GreaterThan,
                threshold: 100.0,
                duration_secs: 300,
                enabled: true,
                metadata: HashMap::new(),
            },
            AlertRule {
                name: "high_memory_usage".to_string(),
                description: "High memory usage detected".to_string(),
                level: AlertLevel::Critical,
                metric: "memory_usage_percent".to_string(),
                condition: AlertCondition::GreaterThan,
                threshold: 90.0,
                duration_secs: 180,
                enabled: true,
                metadata: HashMap::new(),
            },
        ]
    }
}

/// Alert instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert ID
    pub id: String,
    /// Rule name that triggered this alert
    pub rule_name: String,
    /// Alert level
    pub level: AlertLevel,
    /// Alert title
    pub title: String,
    /// Alert description
    pub description: String,
    /// Current metric value
    pub current_value: f64,
    /// Threshold value
    pub threshold_value: f64,
    /// Alert timestamp
    pub timestamp: u64,
    /// Alert status
    pub status: AlertStatus,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Alert status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    /// Alert is active
    Active,
    /// Alert has been resolved
    Resolved,
    /// Alert has been suppressed
    Suppressed,
}

/// Alert manager implementation
pub struct AlertManager {
    config: AlertConfig,
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,
    alert_history: Arc<RwLock<Vec<Alert>>>,
    rule_states: Arc<RwLock<HashMap<String, RuleState>>>,
    http_client: reqwest::Client,
}

/// Rule state for tracking violations
#[derive(Debug, Clone)]
struct RuleState {
    /// When the violation started
    violation_start: Option<SystemTime>,
    /// Last alert sent timestamp
    last_alert_sent: Option<SystemTime>,
    /// Number of alerts sent in current hour
    alerts_sent_this_hour: u32,
    /// Hour of last alert count reset
    last_hour_reset: u32,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(config: AlertConfig) -> DnsResult<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| DnsError::ConfigError(format!("Failed to create HTTP client: {}", e)))?;
        
        Ok(Self {
            config,
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            alert_history: Arc::new(RwLock::new(Vec::new())),
            rule_states: Arc::new(RwLock::new(HashMap::new())),
            http_client,
        })
    }
    
    /// Start the alert manager
    pub async fn start(&self) -> DnsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let active_alerts = self.active_alerts.clone();
        let alert_history = self.alert_history.clone();
        let rule_states = self.rule_states.clone();
        let config = self.config.clone();
        let http_client = self.http_client.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.check_interval_secs));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::check_alert_rules(
                    &config,
                    &active_alerts,
                    &alert_history,
                    &rule_states,
                    &http_client,
                ).await {
                    tracing::error!(error = %e, "Failed to check alert rules");
                }
            }
        });
        
        tracing::info!(
            rules_count = self.config.rules.len(),
            webhooks_count = self.config.webhooks.len(),
            "Alert manager started"
        );
        
        Ok(())
    }
    
    /// Stop the alert manager
    pub async fn stop(&self) -> DnsResult<()> {
        tracing::info!("Alert manager stopped");
        Ok(())
    }
    
    /// Check all alert rules
    async fn check_alert_rules(
        config: &AlertConfig,
        active_alerts: &Arc<RwLock<HashMap<String, Alert>>>,
        alert_history: &Arc<RwLock<Vec<Alert>>>,
        rule_states: &Arc<RwLock<HashMap<String, RuleState>>>,
        http_client: &reqwest::Client,
    ) -> DnsResult<()> {
        let metrics = global_metrics().snapshot();
        let now = SystemTime::now();
        
        for rule in &config.rules {
            if !rule.enabled {
                continue;
            }
            
            // Get current metric value
            let current_value = Self::get_metric_value(&metrics, &rule.metric);
            
            // Check if condition is met
            let condition_met = Self::evaluate_condition(&rule.condition, current_value, rule.threshold);
            
            // Update rule state
            let mut states = rule_states.write().await;
            let state = states.entry(rule.name.clone()).or_insert_with(|| RuleState {
                violation_start: None,
                last_alert_sent: None,
                alerts_sent_this_hour: 0,
                last_hour_reset: 0,
            });
            
            // Reset hourly counter if needed
            let current_hour = now.duration_since(UNIX_EPOCH).unwrap().as_secs() / 3600;
            if state.last_hour_reset != current_hour as u32 {
                state.alerts_sent_this_hour = 0;
                state.last_hour_reset = current_hour as u32;
            }
            
            if condition_met {
                // Start tracking violation if not already started
                if state.violation_start.is_none() {
                    state.violation_start = Some(now);
                }
                
                // Check if duration threshold is met
                let violation_duration = now.duration_since(state.violation_start.unwrap()).unwrap();
                if violation_duration.as_secs() >= rule.duration_secs {
                    // Check if we should send an alert (suppression logic)
                    let should_alert = Self::should_send_alert(config, state, now);
                    
                    if should_alert {
                        let alert = Self::create_alert(rule, current_value, now);
                        
                        // Send alert
                        Self::send_alert(config, &alert, http_client).await?;
                        
                        // Update state
                        state.last_alert_sent = Some(now);
                        state.alerts_sent_this_hour += 1;
                        
                        // Store alert
                        active_alerts.write().await.insert(alert.id.clone(), alert.clone());
                        alert_history.write().await.push(alert);
                        
                        tracing::warn!(
                            rule = %rule.name,
                            current_value = current_value,
                            threshold = rule.threshold,
                            "Alert triggered"
                        );
                    }
                }
            } else {
                // Condition not met, resolve any active alerts
                if state.violation_start.is_some() {
                    state.violation_start = None;
                    
                    // Check if there's an active alert to resolve
                    let mut alerts = active_alerts.write().await;
                    if let Some(alert) = alerts.values_mut().find(|a| a.rule_name == rule.name && a.status == AlertStatus::Active) {
                        alert.status = AlertStatus::Resolved;
                        
                        // Send resolution notification
                        let resolution_alert = Self::create_resolution_alert(rule, current_value, now);
                        if let Err(e) = Self::send_alert(config, &resolution_alert, http_client).await {
                            tracing::error!(error = %e, "Failed to send resolution alert");
                        }
                        
                        tracing::info!(
                            rule = %rule.name,
                            current_value = current_value,
                            "Alert resolved"
                        );
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Get metric value by name
    fn get_metric_value(metrics: &dns_core::MetricsSnapshot, metric_name: &str) -> f64 {
        match metric_name {
            "error_rate_percent" => {
                let total_errors = metrics.protocol_errors + metrics.storage_errors + 
                                 metrics.network_errors + metrics.timeout_errors;
                if metrics.queries_total > 0 {
                    (total_errors as f64 / metrics.queries_total as f64) * 100.0
                } else {
                    0.0
                }
            }
            "cache_hit_rate_percent" => metrics.cache_hit_rate as f64 / 100.0,
            "avg_response_time_ms" => metrics.average_response_time_ns as f64 / 1_000_000.0,
            "memory_usage_percent" => {
                // This would need to be calculated from system metrics
                0.0 // Placeholder
            }
            "queries_per_second" => metrics.queries_per_second as f64,
            "active_connections" => metrics.active_connections as f64,
            "blocked_queries_rate" => {
                if metrics.queries_total > 0 {
                    (metrics.blocked_queries as f64 / metrics.queries_total as f64) * 100.0
                } else {
                    0.0
                }
            }
            _ => 0.0, // Unknown metric
        }
    }
    
    /// Evaluate alert condition
    fn evaluate_condition(condition: &AlertCondition, current_value: f64, threshold: f64) -> bool {
        match condition {
            AlertCondition::GreaterThan => current_value > threshold,
            AlertCondition::LessThan => current_value < threshold,
            AlertCondition::EqualTo => (current_value - threshold).abs() < f64::EPSILON,
            AlertCondition::NotEqualTo => (current_value - threshold).abs() >= f64::EPSILON,
            AlertCondition::GreaterThanOrEqual => current_value >= threshold,
            AlertCondition::LessThanOrEqual => current_value <= threshold,
        }
    }
    
    /// Check if an alert should be sent based on suppression rules
    fn should_send_alert(config: &AlertConfig, state: &RuleState, now: SystemTime) -> bool {
        if !config.suppression.enabled {
            return true;
        }
        
        // Check minimum interval
        if let Some(last_sent) = state.last_alert_sent {
            let time_since_last = now.duration_since(last_sent).unwrap_or(Duration::ZERO);
            if time_since_last.as_secs() < config.suppression.min_interval_secs {
                return false;
            }
        }
        
        // Check hourly limit
        if state.alerts_sent_this_hour >= config.suppression.max_alerts_per_hour {
            return false;
        }
        
        // Check maintenance windows
        if Self::is_in_maintenance_window(config, now) {
            return false;
        }
        
        true
    }
    
    /// Check if current time is in a maintenance window
    fn is_in_maintenance_window(config: &AlertConfig, _now: SystemTime) -> bool {
        // This would implement maintenance window checking
        // For now, we'll return false (no maintenance windows active)
        false
    }
    
    /// Create an alert instance
    fn create_alert(rule: &AlertRule, current_value: f64, timestamp: SystemTime) -> Alert {
        let timestamp_secs = timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let id = format!("{}_{}", rule.name, timestamp_secs);
        
        Alert {
            id,
            rule_name: rule.name.clone(),
            level: rule.level.clone(),
            title: format!("Alert: {}", rule.name),
            description: format!(
                "{} - Current value: {:.2}, Threshold: {:.2}",
                rule.description, current_value, rule.threshold
            ),
            current_value,
            threshold_value: rule.threshold,
            timestamp: timestamp_secs,
            status: AlertStatus::Active,
            metadata: rule.metadata.clone(),
        }
    }
    
    /// Create a resolution alert
    fn create_resolution_alert(rule: &AlertRule, current_value: f64, timestamp: SystemTime) -> Alert {
        let timestamp_secs = timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let id = format!("{}_resolved_{}", rule.name, timestamp_secs);
        
        Alert {
            id,
            rule_name: rule.name.clone(),
            level: AlertLevel::Info,
            title: format!("Resolved: {}", rule.name),
            description: format!(
                "{} has been resolved - Current value: {:.2}",
                rule.description, current_value
            ),
            current_value,
            threshold_value: rule.threshold,
            timestamp: timestamp_secs,
            status: AlertStatus::Resolved,
            metadata: rule.metadata.clone(),
        }
    }
    
    /// Send alert to configured webhooks
    async fn send_alert(
        config: &AlertConfig,
        alert: &Alert,
        http_client: &reqwest::Client,
    ) -> DnsResult<()> {
        for webhook in &config.webhooks {
            if webhook.alert_levels.contains(&alert.level) {
                if let Err(e) = Self::send_webhook(webhook, alert, http_client).await {
                    tracing::error!(
                        webhook = %webhook.name,
                        error = %e,
                        "Failed to send webhook"
                    );
                }
            }
        }
        Ok(())
    }
    
    /// Send webhook notification
    async fn send_webhook(
        webhook: &WebhookConfig,
        alert: &Alert,
        http_client: &reqwest::Client,
    ) -> DnsResult<()> {
        let payload = serde_json::json!({
            "alert": alert,
            "webhook": webhook.name,
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        });
        
        let mut request = match webhook.method.to_uppercase().as_str() {
            "GET" => http_client.get(&webhook.url),
            "POST" => http_client.post(&webhook.url).json(&payload),
            "PUT" => http_client.put(&webhook.url).json(&payload),
            _ => return Err(DnsError::ConfigError(format!("Unsupported HTTP method: {}", webhook.method))),
        };
        
        // Add headers
        for (key, value) in &webhook.headers {
            request = request.header(key, value);
        }
        
        // Send with retries
        let mut retries = 0;
        let mut delay = Duration::from_secs(webhook.retry.initial_delay_secs);
        
        loop {
            match request.try_clone().unwrap().send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        tracing::debug!(
                            webhook = %webhook.name,
                            status = %response.status(),
                            "Webhook sent successfully"
                        );
                        return Ok(());
                    } else {
                        tracing::warn!(
                            webhook = %webhook.name,
                            status = %response.status(),
                            "Webhook returned error status"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        webhook = %webhook.name,
                        error = %e,
                        retry = retries,
                        "Webhook request failed"
                    );
                }
            }
            
            retries += 1;
            if retries > webhook.retry.max_retries {
                return Err(DnsError::ConfigError(format!("Webhook {} failed after {} retries", webhook.name, retries)));
            }
            
            tokio::time::sleep(delay).await;
            delay = Duration::from_secs(
                (delay.as_secs() as f64 * webhook.retry.backoff_multiplier) as u64
                    .min(webhook.retry.max_delay_secs)
            );
        }
    }
    
    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.read().await.values().cloned().collect()
    }
    
    /// Get alert history
    pub async fn get_alert_history(&self, limit: Option<usize>) -> Vec<Alert> {
        let history = self.alert_history.read().await;
        let limit = limit.unwrap_or(history.len());
        history.iter().rev().take(limit).cloned().collect()
    }
    
    /// Manually trigger an alert
    pub async fn trigger_alert(&self, rule_name: &str, message: &str) -> DnsResult<()> {
        let rule = self.config.rules.iter()
            .find(|r| r.name == rule_name)
            .ok_or_else(|| DnsError::ConfigError(format!("Alert rule '{}' not found", rule_name)))?;
        
        let now = SystemTime::now();
        let mut alert = Self::create_alert(rule, 0.0, now);
        alert.description = message.to_string();
        
        Self::send_alert(&self.config, &alert, &self.http_client).await?;
        
        self.active_alerts.write().await.insert(alert.id.clone(), alert.clone());
        self.alert_history.write().await.push(alert);
        
        Ok(())
    }
    
    /// Resolve an active alert
    pub async fn resolve_alert(&self, alert_id: &str) -> DnsResult<()> {
        let mut alerts = self.active_alerts.write().await;
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Resolved;
            tracing::info!(alert_id = %alert_id, "Alert manually resolved");
            Ok(())
        } else {
            Err(DnsError::ConfigError(format!("Alert '{}' not found", alert_id)))
        }
    }
}