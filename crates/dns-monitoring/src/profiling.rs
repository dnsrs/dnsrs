//! Performance profiling and flame graph generation
//!
//! Provides CPU profiling, memory profiling, and flame graph generation
//! for performance analysis and optimization.

use dns_core::{DnsResult, DnsError};
use pprof::ProfilerGuard;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;

/// Configuration for performance profiling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingConfig {
    /// Enable profiling
    pub enabled: bool,
    /// CPU profiling configuration
    pub cpu: CpuProfilingConfig,
    /// Memory profiling configuration
    pub memory: MemoryProfilingConfig,
    /// Flame graph configuration
    pub flamegraph: FlamegraphConfig,
    /// Output directory for profile files
    pub output_dir: PathBuf,
    /// Automatic profiling intervals
    pub auto_profile: AutoProfilingConfig,
}

/// CPU profiling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuProfilingConfig {
    /// Enable CPU profiling
    pub enabled: bool,
    /// Sampling frequency in Hz
    pub frequency: i32,
    /// Duration for automatic CPU profiles in seconds
    pub duration_secs: u64,
    /// Enable stack trace collection
    pub stack_traces: bool,
}

/// Memory profiling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProfilingConfig {
    /// Enable memory profiling
    pub enabled: bool,
    /// Sampling rate (1 in N allocations)
    pub sampling_rate: u32,
    /// Track allocation stack traces
    pub track_allocations: bool,
    /// Track deallocation stack traces
    pub track_deallocations: bool,
}

/// Flame graph configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlamegraphConfig {
    /// Enable flame graph generation
    pub enabled: bool,
    /// Flame graph title
    pub title: String,
    /// Width of the flame graph in pixels
    pub width: u32,
    /// Height of the flame graph in pixels
    pub height: u32,
    /// Color scheme for the flame graph
    pub color_scheme: ColorScheme,
}

/// Flame graph color schemes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ColorScheme {
    /// Hot colors (red/orange/yellow)
    Hot,
    /// Cool colors (blue/green)
    Cool,
    /// Aqua colors
    Aqua,
    /// Java-style colors
    Java,
    /// Random colors
    Random,
}

/// Automatic profiling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoProfilingConfig {
    /// Enable automatic profiling
    pub enabled: bool,
    /// Interval between automatic profiles in seconds
    pub interval_secs: u64,
    /// Maximum number of profile files to keep
    pub max_files: u32,
    /// Enable profiling on high CPU usage
    pub cpu_threshold_percent: f64,
    /// Enable profiling on high memory usage
    pub memory_threshold_percent: f64,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for production
            cpu: CpuProfilingConfig {
                enabled: true,
                frequency: 100, // 100 Hz
                duration_secs: 30,
                stack_traces: true,
            },
            memory: MemoryProfilingConfig {
                enabled: false, // Memory profiling can be expensive
                sampling_rate: 1000, // 1 in 1000 allocations
                track_allocations: true,
                track_deallocations: false,
            },
            flamegraph: FlamegraphConfig {
                enabled: true,
                title: "DNS Server CPU Profile".to_string(),
                width: 1200,
                height: 800,
                color_scheme: ColorScheme::Hot,
            },
            output_dir: PathBuf::from("./profiles"),
            auto_profile: AutoProfilingConfig {
                enabled: false,
                interval_secs: 300, // 5 minutes
                max_files: 20,
                cpu_threshold_percent: 80.0,
                memory_threshold_percent: 85.0,
            },
        }
    }
}

/// Profile manager for performance profiling
pub struct ProfileManager {
    config: ProfilingConfig,
    active_profilers: Arc<RwLock<HashMap<String, ProfilerGuard<'static>>>>,
    profile_stats: Arc<RwLock<ProfileStats>>,
}

/// Profile statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileStats {
    /// Total number of profiles generated
    pub total_profiles: u64,
    /// CPU profiles generated
    pub cpu_profiles: u64,
    /// Memory profiles generated
    pub memory_profiles: u64,
    /// Flame graphs generated
    pub flamegraphs: u64,
    /// Last profile timestamp
    pub last_profile_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Average profile generation time in milliseconds
    pub avg_generation_time_ms: f64,
}

impl Default for ProfileStats {
    fn default() -> Self {
        Self {
            total_profiles: 0,
            cpu_profiles: 0,
            memory_profiles: 0,
            flamegraphs: 0,
            last_profile_time: None,
            avg_generation_time_ms: 0.0,
        }
    }
}

/// Profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    /// Profile ID
    pub id: String,
    /// Profile type
    pub profile_type: ProfileType,
    /// Start time
    pub start_time: chrono::DateTime<chrono::Utc>,
    /// End time
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Duration in seconds
    pub duration_secs: f64,
    /// File path
    pub file_path: PathBuf,
    /// File size in bytes
    pub file_size: u64,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Profile types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProfileType {
    /// CPU profile
    Cpu,
    /// Memory profile
    Memory,
    /// Flame graph
    Flamegraph,
}

impl ProfileManager {
    /// Create a new profile manager
    pub fn new(config: ProfilingConfig) -> DnsResult<Self> {
        // Create output directory if it doesn't exist
        if config.enabled {
            std::fs::create_dir_all(&config.output_dir)
                .map_err(|e| DnsError::ConfigError(format!("Failed to create profile output directory: {}", e)))?;
        }
        
        Ok(Self {
            config,
            active_profilers: Arc::new(RwLock::new(HashMap::new())),
            profile_stats: Arc::new(RwLock::new(ProfileStats::default())),
        })
    }
    
    /// Start the profiling system
    pub async fn start(&self) -> DnsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        // Start automatic profiling if enabled
        if self.config.auto_profile.enabled {
            self.start_auto_profiling().await?;
        }
        
        tracing::info!(
            cpu_enabled = self.config.cpu.enabled,
            memory_enabled = self.config.memory.enabled,
            flamegraph_enabled = self.config.flamegraph.enabled,
            output_dir = %self.config.output_dir.display(),
            "Performance profiling started"
        );
        
        Ok(())
    }
    
    /// Stop the profiling system
    pub async fn stop(&self) -> DnsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        // Stop all active profilers
        let mut profilers = self.active_profilers.write().await;
        for (id, _profiler) in profilers.drain() {
            tracing::debug!(profile_id = %id, "Stopping active profiler");
        }
        
        tracing::info!("Performance profiling stopped");
        Ok(())
    }
    
    /// Start CPU profiling
    pub async fn start_cpu_profile(&self, profile_id: Option<String>) -> DnsResult<String> {
        if !self.config.enabled || !self.config.cpu.enabled {
            return Err(DnsError::ConfigError("CPU profiling is not enabled".to_string()));
        }
        
        let id = profile_id.unwrap_or_else(|| {
            format!("cpu_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"))
        });
        
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(self.config.cpu.frequency)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
            .map_err(|e| DnsError::ConfigError(format!("Failed to start CPU profiler: {}", e)))?;
        
        let mut profilers = self.active_profilers.write().await;
        profilers.insert(id.clone(), guard);
        
        tracing::info!(profile_id = %id, "CPU profiling started");
        Ok(id)
    }
    
    /// Stop CPU profiling and generate report
    pub async fn stop_cpu_profile(&self, profile_id: &str) -> DnsResult<ProfileInfo> {
        let start_time = Instant::now();
        
        let guard = {
            let mut profilers = self.active_profilers.write().await;
            profilers.remove(profile_id)
                .ok_or_else(|| DnsError::ConfigError(format!("Profile {} not found", profile_id)))?
        };
        
        // Generate profile report
        let report = guard.report().build()
            .map_err(|e| DnsError::ConfigError(format!("Failed to build profile report: {}", e)))?;
        
        // Write profile to file
        let file_path = self.config.output_dir.join(format!("{}.pb", profile_id));
        let mut file = File::create(&file_path)
            .map_err(|e| DnsError::ConfigError(format!("Failed to create profile file: {}", e)))?;
        
        let profile = report.pprof()
            .map_err(|e| DnsError::ConfigError(format!("Failed to generate pprof: {}", e)))?;
        
        profile.write_to_writer(&mut file)
            .map_err(|e| DnsError::ConfigError(format!("Failed to write profile: {}", e)))?;
        
        // Generate flame graph if enabled
        let mut flamegraph_path = None;
        if self.config.flamegraph.enabled {
            flamegraph_path = Some(self.generate_flamegraph(&report, profile_id).await?);
        }
        
        // Get file size
        let file_size = std::fs::metadata(&file_path)
            .map_err(|e| DnsError::ConfigError(format!("Failed to get file metadata: {}", e)))?
            .len();
        
        // Update statistics
        let mut stats = self.profile_stats.write().await;
        stats.total_profiles += 1;
        stats.cpu_profiles += 1;
        if flamegraph_path.is_some() {
            stats.flamegraphs += 1;
        }
        stats.last_profile_time = Some(chrono::Utc::now());
        
        let generation_time = start_time.elapsed().as_millis() as f64;
        stats.avg_generation_time_ms = 
            (stats.avg_generation_time_ms * (stats.total_profiles - 1) as f64 + generation_time) / stats.total_profiles as f64;
        
        let mut metadata = HashMap::new();
        metadata.insert("frequency".to_string(), serde_json::Value::Number(self.config.cpu.frequency.into()));
        if let Some(fg_path) = flamegraph_path {
            metadata.insert("flamegraph_path".to_string(), serde_json::Value::String(fg_path.to_string_lossy().to_string()));
        }
        
        let profile_info = ProfileInfo {
            id: profile_id.to_string(),
            profile_type: ProfileType::Cpu,
            start_time: chrono::Utc::now() - chrono::Duration::milliseconds(generation_time as i64),
            end_time: Some(chrono::Utc::now()),
            duration_secs: generation_time / 1000.0,
            file_path,
            file_size,
            metadata,
        };
        
        tracing::info!(
            profile_id = %profile_id,
            file_size = file_size,
            generation_time_ms = generation_time,
            "CPU profile generated"
        );
        
        Ok(profile_info)
    }
    
    /// Generate a flame graph from a profile report
    async fn generate_flamegraph(
        &self,
        report: &pprof::Report,
        profile_id: &str,
    ) -> DnsResult<PathBuf> {
        let flamegraph_path = self.config.output_dir.join(format!("{}.svg", profile_id));
        let file = File::create(&flamegraph_path)
            .map_err(|e| DnsError::ConfigError(format!("Failed to create flamegraph file: {}", e)))?;
        
        let mut options = pprof::flamegraph::Options::default();
        options.title = self.config.flamegraph.title.clone();
        options.width = self.config.flamegraph.width;
        options.height = self.config.flamegraph.height;
        
        // Set color scheme
        match self.config.flamegraph.color_scheme {
            ColorScheme::Hot => options.colors = pprof::flamegraph::color::Palette::Hot,
            ColorScheme::Cool => options.colors = pprof::flamegraph::color::Palette::Cool,
            ColorScheme::Aqua => options.colors = pprof::flamegraph::color::Palette::Aqua,
            ColorScheme::Java => options.colors = pprof::flamegraph::color::Palette::Java,
            ColorScheme::Random => options.colors = pprof::flamegraph::color::Palette::Random,
        }
        
        report.flamegraph_with_options(file, &mut options)
            .map_err(|e| DnsError::ConfigError(format!("Failed to generate flamegraph: {}", e)))?;
        
        Ok(flamegraph_path)
    }
    
    /// Start automatic profiling
    async fn start_auto_profiling(&self) -> DnsResult<()> {
        let config = self.config.clone();
        let profile_manager = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.auto_profile.interval_secs));
            
            loop {
                interval.tick().await;
                
                // Check if we should profile based on system metrics
                if Self::should_auto_profile(&config).await {
                    if let Err(e) = Self::perform_auto_profile(&profile_manager).await {
                        tracing::error!(error = %e, "Automatic profiling failed");
                    }
                }
                
                // Clean up old profile files
                if let Err(e) = Self::cleanup_old_profiles(&config).await {
                    tracing::warn!(error = %e, "Failed to clean up old profiles");
                }
            }
        });
        
        Ok(())
    }
    
    /// Check if automatic profiling should be triggered
    async fn should_auto_profile(config: &ProfilingConfig) -> bool {
        // This would typically check system metrics
        // For now, we'll always return true if auto profiling is enabled
        config.auto_profile.enabled
    }
    
    /// Perform automatic profiling
    async fn perform_auto_profile(profile_manager: &Arc<ProfileManager>) -> DnsResult<()> {
        let profile_id = format!("auto_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        
        // Start CPU profile
        let id = profile_manager.start_cpu_profile(Some(profile_id)).await?;
        
        // Wait for the configured duration
        tokio::time::sleep(Duration::from_secs(profile_manager.config.cpu.duration_secs)).await;
        
        // Stop and generate profile
        let _profile_info = profile_manager.stop_cpu_profile(&id).await?;
        
        tracing::info!(profile_id = %id, "Automatic profile completed");
        Ok(())
    }
    
    /// Clean up old profile files
    async fn cleanup_old_profiles(config: &ProfilingConfig) -> DnsResult<()> {
        let mut entries = std::fs::read_dir(&config.output_dir)
            .map_err(|e| DnsError::ConfigError(format!("Failed to read profile directory: {}", e)))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.path().extension()
                    .map(|ext| ext == "pb" || ext == "svg")
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        
        // Sort by modification time (newest first)
        entries.sort_by_key(|entry| {
            entry.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });
        entries.reverse();
        
        // Remove old files if we exceed the limit
        if entries.len() > config.auto_profile.max_files as usize {
            for entry in entries.iter().skip(config.auto_profile.max_files as usize) {
                if let Err(e) = std::fs::remove_file(entry.path()) {
                    tracing::warn!(
                        file = %entry.path().display(),
                        error = %e,
                        "Failed to remove old profile file"
                    );
                }
            }
        }
        
        Ok(())
    }
    
    /// Get profiling statistics
    pub async fn get_stats(&self) -> ProfileStats {
        self.profile_stats.read().await.clone()
    }
    
    /// List available profiles
    pub async fn list_profiles(&self) -> DnsResult<Vec<ProfileInfo>> {
        let mut profiles = Vec::new();
        
        let entries = std::fs::read_dir(&self.config.output_dir)
            .map_err(|e| DnsError::ConfigError(format!("Failed to read profile directory: {}", e)))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| DnsError::ConfigError(format!("Failed to read directory entry: {}", e)))?;
            let path = entry.path();
            
            if let Some(extension) = path.extension() {
                if extension == "pb" {
                    if let Some(stem) = path.file_stem() {
                        let id = stem.to_string_lossy().to_string();
                        let metadata = entry.metadata()
                            .map_err(|e| DnsError::ConfigError(format!("Failed to read file metadata: {}", e)))?;
                        
                        let profile_info = ProfileInfo {
                            id: id.clone(),
                            profile_type: ProfileType::Cpu,
                            start_time: chrono::DateTime::from(metadata.created().unwrap_or(std::time::SystemTime::UNIX_EPOCH)),
                            end_time: Some(chrono::DateTime::from(metadata.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))),
                            duration_secs: 0.0, // Would need to be stored separately
                            file_path: path.clone(),
                            file_size: metadata.len(),
                            metadata: HashMap::new(),
                        };
                        
                        profiles.push(profile_info);
                    }
                }
            }
        }
        
        // Sort by creation time (newest first)
        profiles.sort_by(|a, b| b.start_time.cmp(&a.start_time));
        
        Ok(profiles)
    }
    
    /// Check if profiling is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

// Implement Clone for ProfileManager to support Arc usage
impl Clone for ProfileManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            active_profilers: self.active_profilers.clone(),
            profile_stats: self.profile_stats.clone(),
        }
    }
}