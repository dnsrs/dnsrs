//! Zero-copy network layer for cluster communications
//!
//! Implements high-performance network protocols for zone transfers,
//! health checks, and cluster coordination using zero-copy techniques.

use crate::{Result, ClusterError, ZoneTransferHeader, CompressionType};
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{RwLock, Semaphore};
use lockfree::map::Map as LockFreeMap;
use tracing::{info, warn, error, debug};

/// Zero-copy network manager for cluster communications
pub struct ZeroCopyNetworkManager {
    // Connection pools
    tcp_connections: Arc<LockFreeMap<u64, Arc<TcpConnectionPool>>>,
    udp_sockets: Arc<LockFreeMap<u64, Arc<UdpSocketPool>>>,
    
    // Network configuration
    config: NetworkConfig,
    
    // Network statistics
    stats: Arc<NetworkStats>,
    
    // Connection limits
    connection_semaphore: Arc<Semaphore>,
    
    // Running state
    is_running: AtomicBool,
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub max_connections_per_node: usize,
    pub connection_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub max_frame_size: usize,
    pub enable_compression: bool,
    pub compression_threshold: usize,
    pub tcp_nodelay: bool,
    pub tcp_keepalive: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_connections_per_node: 10,
            connection_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(60),
            max_frame_size: 16 * 1024 * 1024, // 16MB
            enable_compression: true,
            compression_threshold: 1024, // 1KB
            tcp_nodelay: true,
            tcp_keepalive: true,
        }
    }
}

/// Network statistics
pub struct NetworkStats {
    pub connections_created: AtomicU64,
    pub connections_closed: AtomicU64,
    pub connections_failed: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
    pub compression_savings: AtomicU64,
    pub network_errors: AtomicU64,
    pub active_connections: AtomicUsize,
}

impl NetworkStats {
    pub fn new() -> Self {
        Self {
            connections_created: AtomicU64::new(0),
            connections_closed: AtomicU64::new(0),
            connections_failed: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            compression_savings: AtomicU64::new(0),
            network_errors: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }
}

impl ZeroCopyNetworkManager {
    pub fn new(config: NetworkConfig) -> Self {
        let max_connections = config.max_connections_per_node * 1000; // Assume max 1000 nodes
        
        Self {
            tcp_connections: Arc::new(LockFreeMap::new()),
            udp_sockets: Arc::new(LockFreeMap::new()),
            config,
            stats: Arc::new(NetworkStats::new()),
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
            is_running: AtomicBool::new(false),
        }
    }
    
    /// Start the network manager
    pub async fn start(&self, bind_address: SocketAddr) -> Result<()> {
        if self.is_running.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        
        info!("Starting zero-copy network manager on {}", bind_address);
        
        // Start TCP server
        self.start_tcp_server(bind_address).await?;
        
        // Start UDP server
        self.start_udp_server(bind_address).await?;
        
        // Start connection cleanup task
        self.start_cleanup_task().await;
        
        Ok(())
    }
    
    /// Send data to a node using zero-copy techniques
    pub async fn send_to_node(&self, node_id: u64, address: SocketAddr, data: &[u8]) -> Result<()> {
        let pool = self.get_or_create_tcp_pool(node_id, address).await?;
        let connection = pool.get_connection().await?;
        
        connection.send_frame(data).await?;
        
        self.stats.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// Send zone data using optimized transfer protocol
    pub async fn send_zone_data(&self, node_id: u64, address: SocketAddr, zone_hash: u64, data: &[u8]) -> Result<()> {
        let header = ZoneTransferHeader {
            zone_hash,
            data_size: data.len() as u64,
            compression: if self.config.enable_compression && data.len() > self.config.compression_threshold {
                CompressionType::Lz4
            } else {
                CompressionType::None
            },
            version: 1,
        };
        
        let pool = self.get_or_create_tcp_pool(node_id, address).await?;
        let connection = pool.get_connection().await?;
        
        // Send header first
        connection.send_frame(&header.to_bytes()).await?;
        
        // Send data (potentially compressed)
        let final_data = if header.compression != CompressionType::None {
            self.compress_data(data).await?
        } else {
            data.to_vec()
        };
        
        connection.send_frame(&final_data).await?;
        
        self.stats.bytes_sent.fetch_add((header.to_bytes().len() + final_data.len()) as u64, Ordering::Relaxed);
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        
        if header.compression != CompressionType::None {
            let savings = data.len().saturating_sub(final_data.len()) as u64;
            self.stats.compression_savings.fetch_add(savings, Ordering::Relaxed);
        }
        
        Ok(())
    }
    
    /// Get network statistics
    pub fn get_stats(&self) -> NetworkStatsSnapshot {
        NetworkStatsSnapshot {
            connections_created: self.stats.connections_created.load(Ordering::Relaxed),
            connections_closed: self.stats.connections_closed.load(Ordering::Relaxed),
            connections_failed: self.stats.connections_failed.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            messages_sent: self.stats.messages_sent.load(Ordering::Relaxed),
            messages_received: self.stats.messages_received.load(Ordering::Relaxed),
            compression_savings: self.stats.compression_savings.load(Ordering::Relaxed),
            network_errors: self.stats.network_errors.load(Ordering::Relaxed),
            active_connections: self.stats.active_connections.load(Ordering::Relaxed),
        }
    }
    
    async fn get_or_create_tcp_pool(&self, node_id: u64, address: SocketAddr) -> Result<Arc<TcpConnectionPool>> {
        if let Some(pool) = self.tcp_connections.get(&node_id) {
            return Ok(pool.val().clone());
        }
        
        let pool = Arc::new(TcpConnectionPool::new(
            node_id,
            address,
            self.config.clone(),
            Arc::clone(&self.stats),
            Arc::clone(&self.connection_semaphore),
        ));
        
        self.tcp_connections.insert(node_id, Arc::clone(&pool));
        
        Ok(pool)
    }
    
    async fn start_tcp_server(&self, bind_address: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_address).await
            .map_err(ClusterError::Network)?;
        
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();
        let connection_semaphore = Arc::clone(&self.connection_semaphore);
        
        tokio::spawn(async move {
            info!("TCP server listening on {}", bind_address);
            
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let stats = Arc::clone(&stats);
                        let config = config.clone();
                        let connection_semaphore = Arc::clone(&connection_semaphore);
                        
                        tokio::spawn(async move {
                            if let Ok(_permit) = connection_semaphore.acquire().await {
                                stats.connections_created.fetch_add(1, Ordering::Relaxed);
                                stats.active_connections.fetch_add(1, Ordering::Relaxed);
                                
                                if let Err(e) = Self::handle_tcp_connection(stream, peer_addr, stats.clone(), config).await {
                                    warn!("TCP connection error from {}: {}", peer_addr, e);
                                    stats.network_errors.fetch_add(1, Ordering::Relaxed);
                                }
                                
                                stats.connections_closed.fetch_add(1, Ordering::Relaxed);
                                stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept TCP connection: {}", e);
                        stats.network_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    async fn start_udp_server(&self, bind_address: SocketAddr) -> Result<()> {
        let socket = UdpSocket::bind(bind_address).await
            .map_err(ClusterError::Network)?;
        
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            info!("UDP server listening on {}", bind_address);
            
            let mut buffer = vec![0u8; 65536]; // Max UDP packet size
            
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((size, peer_addr)) => {
                        stats.bytes_received.fetch_add(size as u64, Ordering::Relaxed);
                        stats.messages_received.fetch_add(1, Ordering::Relaxed);
                        
                        // Handle UDP message
                        debug!("Received UDP message from {}: {} bytes", peer_addr, size);
                    }
                    Err(e) => {
                        error!("UDP receive error: {}", e);
                        stats.network_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    async fn handle_tcp_connection(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        stats: Arc<NetworkStats>,
        config: NetworkConfig,
    ) -> Result<()> {
        debug!("Handling TCP connection from {}", peer_addr);
        
        // Configure socket options
        if config.tcp_nodelay {
            let _ = stream.set_nodelay(true);
        }
        
        let mut buffer = vec![0u8; config.max_frame_size];
        
        loop {
            // Read frame length (4 bytes)
            let mut length_bytes = [0u8; 4];
            match tokio::time::timeout(config.read_timeout, stream.read_exact(&mut length_bytes)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!("Connection closed by peer {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    debug!("Read timeout from {}", peer_addr);
                    break;
                }
            }
            
            let frame_length = u32::from_be_bytes(length_bytes) as usize;
            
            if frame_length > config.max_frame_size {
                warn!("Frame too large from {}: {} bytes", peer_addr, frame_length);
                break;
            }
            
            // Read frame data
            buffer.resize(frame_length, 0);
            match tokio::time::timeout(config.read_timeout, stream.read_exact(&mut buffer)).await {
                Ok(Ok(_)) => {
                    stats.bytes_received.fetch_add((4 + frame_length) as u64, Ordering::Relaxed);
                    stats.messages_received.fetch_add(1, Ordering::Relaxed);
                    
                    // Process frame
                    debug!("Received frame from {}: {} bytes", peer_addr, frame_length);
                }
                Ok(Err(e)) => {
                    debug!("Connection error from {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    debug!("Read timeout from {}", peer_addr);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    async fn start_cleanup_task(&self) {
        let tcp_connections = Arc::clone(&self.tcp_connections);
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
            
            loop {
                cleanup_interval.tick().await;
                
                // Clean up idle connections
                let mut removed_count = 0;
                
                for guard in tcp_connections.iter() {
                    let pool = guard.val();
                    if pool.should_cleanup().await {
                        tcp_connections.remove(guard.key());
                        removed_count += 1;
                    }
                }
                
                if removed_count > 0 {
                    debug!("Cleaned up {} idle connection pools", removed_count);
                }
            }
        });
    }
    
    async fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Placeholder for compression
        // In a real implementation, this would use LZ4 or Zstd
        Ok(data.to_vec())
    }
}

/// TCP connection pool for a specific node
pub struct TcpConnectionPool {
    node_id: u64,
    address: SocketAddr,
    connections: Arc<RwLock<Vec<Arc<TcpConnection>>>>,
    config: NetworkConfig,
    stats: Arc<NetworkStats>,
    connection_semaphore: Arc<Semaphore>,
    last_used: AtomicU64,
}

impl TcpConnectionPool {
    pub fn new(
        node_id: u64,
        address: SocketAddr,
        config: NetworkConfig,
        stats: Arc<NetworkStats>,
        connection_semaphore: Arc<Semaphore>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            node_id,
            address,
            connections: Arc::new(RwLock::new(Vec::new())),
            config,
            stats,
            connection_semaphore,
            last_used: AtomicU64::new(now),
        }
    }
    
    pub async fn get_connection(&self) -> Result<Arc<TcpConnection>> {
        self.update_last_used();
        
        // Try to reuse existing connection
        {
            let connections = self.connections.read().await;
            for conn in connections.iter() {
                if conn.is_available() {
                    return Ok(Arc::clone(conn));
                }
            }
        }
        
        // Create new connection if under limit
        {
            let connections = self.connections.read().await;
            if connections.len() >= self.config.max_connections_per_node {
                return Err(ClusterError::InconsistentState);
            }
        }
        
        // Acquire connection permit
        let _permit = self.connection_semaphore.acquire().await
            .map_err(|_| ClusterError::InconsistentState)?;
        
        // Create new connection
        let stream = tokio::time::timeout(
            self.config.connection_timeout,
            TcpStream::connect(self.address)
        ).await
            .map_err(|_| ClusterError::Timeout)?
            .map_err(ClusterError::Network)?;
        
        let connection = Arc::new(TcpConnection::new(stream, self.config.clone()));
        
        // Add to pool
        {
            let mut connections = self.connections.write().await;
            connections.push(Arc::clone(&connection));
        }
        
        self.stats.connections_created.fetch_add(1, Ordering::Relaxed);
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);
        
        debug!("Created new TCP connection to node {} at {}", self.node_id, self.address);
        
        Ok(connection)
    }
    
    pub async fn should_cleanup(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let last_used = self.last_used.load(Ordering::Relaxed);
        let idle_time = now.saturating_sub(last_used);
        
        // Cleanup if idle for more than 10 minutes
        idle_time > 600
    }
    
    fn update_last_used(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_used.store(now, Ordering::Relaxed);
    }
}

/// TCP connection wrapper
pub struct TcpConnection {
    stream: Arc<tokio::sync::Mutex<TcpStream>>,
    config: NetworkConfig,
    is_available: AtomicBool,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    last_used: AtomicU64,
}

impl TcpConnection {
    pub fn new(stream: TcpStream, config: NetworkConfig) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            config,
            is_available: AtomicBool::new(true),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_used: AtomicU64::new(now),
        }
    }
    
    pub fn is_available(&self) -> bool {
        self.is_available.load(Ordering::Relaxed)
    }
    
    pub async fn send_frame(&self, data: &[u8]) -> Result<()> {
        if !self.is_available.swap(false, Ordering::AcqRel) {
            return Err(ClusterError::InconsistentState);
        }
        
        let result = self.send_frame_internal(data).await;
        
        self.is_available.store(true, Ordering::Release);
        self.update_last_used();
        
        result
    }
    
    async fn send_frame_internal(&self, data: &[u8]) -> Result<()> {
        let mut stream = self.stream.lock().await;
        
        // Send frame length (4 bytes)
        let length_bytes = (data.len() as u32).to_be_bytes();
        
        tokio::time::timeout(
            self.config.write_timeout,
            stream.write_all(&length_bytes)
        ).await
            .map_err(|_| ClusterError::Timeout)?
            .map_err(ClusterError::Network)?;
        
        // Send frame data
        tokio::time::timeout(
            self.config.write_timeout,
            stream.write_all(data)
        ).await
            .map_err(|_| ClusterError::Timeout)?
            .map_err(ClusterError::Network)?;
        
        // Flush
        tokio::time::timeout(
            self.config.write_timeout,
            stream.flush()
        ).await
            .map_err(|_| ClusterError::Timeout)?
            .map_err(ClusterError::Network)?;
        
        self.bytes_sent.fetch_add((4 + data.len()) as u64, Ordering::Relaxed);
        
        Ok(())
    }
    
    fn update_last_used(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_used.store(now, Ordering::Relaxed);
    }
}

/// UDP socket pool for a specific node
pub struct UdpSocketPool {
    node_id: u64,
    address: SocketAddr,
    socket: Arc<UdpSocket>,
    stats: Arc<NetworkStats>,
}

impl UdpSocketPool {
    pub async fn new(node_id: u64, address: SocketAddr, stats: Arc<NetworkStats>) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(ClusterError::Network)?;
        
        Ok(Self {
            node_id,
            address,
            socket: Arc::new(socket),
            stats,
        })
    }
    
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        self.socket.send_to(data, self.address).await
            .map_err(ClusterError::Network)?;
        
        self.stats.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }
}

/// Network statistics snapshot
#[derive(Debug, Clone)]
pub struct NetworkStatsSnapshot {
    pub connections_created: u64,
    pub connections_closed: u64,
    pub connections_failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub compression_savings: u64,
    pub network_errors: u64,
    pub active_connections: usize,
}