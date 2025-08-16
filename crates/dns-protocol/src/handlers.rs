//! Protocol handlers for different DNS transports

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use bytes::Bytes;
use dns_core::{DnsQuery, DnsResponse, DnsResult, DnsError};

/// Protocol type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    Udp,
    Tcp,
    DoH,    // DNS over HTTPS (RFC 8484)
    DoT,    // DNS over TLS (RFC 7858)
    DoQ,    // DNS over QUIC (RFC 9250)
}

/// Core DNS protocol handler trait
#[async_trait::async_trait]
pub trait DnsProtocolHandler: Send + Sync {
    /// Handle a DNS query and return a response
    async fn handle_query(&self, query: DnsQuery, client_addr: SocketAddr) -> DnsResult<DnsResponse>;
    
    /// Start the protocol listener on the specified address
    async fn start_listener(&self, bind_addr: SocketAddr) -> DnsResult<()>;
    
    /// Get the protocol type
    fn protocol_type(&self) -> ProtocolType;
    
    /// Handle zone synchronization (modern zone transfer)
    async fn handle_zone_sync(&self, sync_request: ZoneSyncRequest, client_addr: SocketAddr) -> DnsResult<ZoneSyncResponse>;
    
    /// Handle dynamic DNS updates
    async fn handle_dynamic_update(&self, update: DynamicUpdate, client_addr: SocketAddr) -> DnsResult<UpdateResponse>;
    
    /// Handle zone change notifications
    async fn handle_zone_notify(&self, notify: ZoneNotify, client_addr: SocketAddr) -> DnsResult<NotifyResponse>;
}

/// Modern zone synchronization request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneSyncRequest {
    pub zone_hash: u64,           // Fast zone identification
    pub last_known_version: u64,  // Version-based sync instead of serial
    pub compression: CompressionType,
    pub auth_token: AuthToken,
}

/// Zone synchronization response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneSyncResponse {
    pub zone_data: Vec<u8>,       // Zero-copy FlatBuffer zone data
    pub version: u64,
    pub delta: bool,              // True if incremental, false if full
    pub compression: CompressionType,
}

/// Dynamic DNS update request
#[derive(Debug, Clone)]
pub struct DynamicUpdate {
    pub zone_hash: u64,
    pub operations: Vec<UpdateOperation>,
    pub auth_token: AuthToken,
    pub expected_version: u64,    // Optimistic concurrency control
}

/// Update operation types
#[derive(Debug, Clone)]
pub enum UpdateOperation {
    Add { name_hash: u64, record_data: Bytes },
    Remove { name_hash: u64, record_type: u16 },
    Replace { name_hash: u64, record_data: Bytes },
}

/// Zone change notification
#[derive(Debug, Clone)]
pub struct ZoneNotify {
    pub zone_hash: u64,
    pub new_version: u64,
    pub change_summary: ChangeSummary,
}

/// Summary of zone changes
#[derive(Debug, Clone)]
pub struct ChangeSummary {
    pub records_added: u32,
    pub records_removed: u32,
    pub records_modified: u32,
    pub affected_names: Vec<u64>, // Hashed domain names
}

/// Compression types for zone transfers
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum CompressionType {
    None,
    Lz4,
    Zstd,
}

/// Authentication token for secure operations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub expires_at: u64,
}

/// Response types
#[derive(Debug, Clone)]
pub struct UpdateResponse {
    pub success: bool,
    pub new_version: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NotifyResponse {
    pub acknowledged: bool,
    pub current_version: u64,
}

/// High-performance UDP DNS handler with SO_REUSEPORT for load balancing
pub struct UdpDnsHandler {
    query_router: Arc<dyn QueryRouter>,
    max_packet_size: usize,
    buffer_pool: Arc<BufferPool>,
}

impl UdpDnsHandler {
    /// Create a new UDP DNS handler
    pub fn new(query_router: Arc<dyn QueryRouter>) -> Self {
        Self {
            query_router,
            max_packet_size: 4096, // Standard DNS UDP packet size limit
            buffer_pool: Arc::new(BufferPool::new(1024)), // Pool of 1024 buffers
        }
    }

    /// Create UDP socket with SO_REUSEPORT for load balancing
    async fn create_socket(bind_addr: SocketAddr) -> DnsResult<UdpSocket> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            use std::os::unix::io::FromRawFd;
            
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(bind_addr),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            ).map_err(|e| DnsError::network_error(e.to_string()))?;
            
            // TODO: Enable SO_REUSEPORT for load balancing across multiple processes
            // This requires a newer version of socket2 or manual socket configuration
            socket.set_reuse_address(true).map_err(|e| DnsError::network_error(e.to_string()))?;
            socket.set_nonblocking(true).map_err(|e| DnsError::network_error(e.to_string()))?;
            
            // Bind to the address
            socket.bind(&bind_addr.into()).map_err(|e| DnsError::network_error(e.to_string()))?;
            
            // Convert to tokio UdpSocket
            let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(socket.as_raw_fd()) };
            std::mem::forget(socket); // Prevent double close
            
            UdpSocket::from_std(std_socket).map_err(|e| DnsError::network_error(e.to_string()))
        }
        
        #[cfg(not(unix))]
        {
            // Fallback for non-Unix systems
            UdpSocket::bind(bind_addr).await.map_err(|e| DnsError::network_error(e.to_string()))
        }
    }

    /// Process incoming UDP packets in a loop
    async fn process_packets(&self, socket: Arc<UdpSocket>) -> DnsResult<()> {
        loop {
            // Get buffer from pool
            let mut buffer = self.buffer_pool.get_buffer().await;
            
            // Receive packet
            match socket.recv_from(&mut buffer).await {
                Ok((len, client_addr)) => {
                    let packet_data = buffer[..len].to_vec();
                    let socket_clone = socket.clone();
                    let router = self.query_router.clone();
                    let buffer_pool = self.buffer_pool.clone();
                    
                    // Process packet asynchronously
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_packet(router, socket_clone, packet_data, client_addr).await {
                            tracing::error!("Failed to handle UDP packet: {}", e);
                        }
                        // Return buffer to pool
                        buffer_pool.return_buffer(buffer).await;
                    });
                }
                Err(e) => {
                    tracing::error!("UDP receive error: {}", e);
                    // Return buffer to pool on error
                    self.buffer_pool.return_buffer(buffer).await;
                }
            }
        }
    }

    /// Handle a single UDP packet
    async fn handle_packet(
        router: Arc<dyn QueryRouter>,
        socket: Arc<UdpSocket>,
        packet_data: Vec<u8>,
        client_addr: SocketAddr,
    ) -> DnsResult<()> {
        // Parse DNS query
        let mut query = DnsQuery::from_bytes(&packet_data)?;
        query.client_addr = client_addr.ip();
        
        // Route query through the query engine
        let response = router.route_query(query, client_addr).await?;
        
        // Send response back to client
        let response_bytes = response.to_bytes()?;
        socket.send_to(&response_bytes, client_addr).await.map_err(|e| DnsError::network_error(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsProtocolHandler for UdpDnsHandler {
    async fn handle_query(&self, query: DnsQuery, client_addr: SocketAddr) -> DnsResult<DnsResponse> {
        self.query_router.route_query(query, client_addr).await
    }

    async fn start_listener(&self, bind_addr: SocketAddr) -> DnsResult<()> {
        tracing::info!("Starting UDP DNS server on {}", bind_addr);
        
        // Create socket with SO_REUSEPORT
        let socket = Arc::new(Self::create_socket(bind_addr).await?);
        
        // Start processing packets
        self.process_packets(socket).await
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Udp
    }

    async fn handle_zone_sync(&self, _sync_request: ZoneSyncRequest, _client_addr: SocketAddr) -> DnsResult<ZoneSyncResponse> {
        Err(DnsError::NotImplemented { feature: "Zone sync not supported over UDP".to_string() })
    }

    async fn handle_dynamic_update(&self, _update: DynamicUpdate, _client_addr: SocketAddr) -> DnsResult<UpdateResponse> {
        Err(DnsError::NotImplemented { feature: "Dynamic updates not supported over UDP".to_string() })
    }

    async fn handle_zone_notify(&self, _notify: ZoneNotify, _client_addr: SocketAddr) -> DnsResult<NotifyResponse> {
        Err(DnsError::NotImplemented { feature: "Zone notify not supported over UDP".to_string() })
    }
}

/// Buffer pool for efficient memory management
pub struct BufferPool {
    buffers: tokio::sync::Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
    max_buffers: usize,
}

impl BufferPool {
    pub fn new(max_buffers: usize) -> Self {
        Self {
            buffers: tokio::sync::Mutex::new(Vec::new()),
            buffer_size: 4096,
            max_buffers,
        }
    }

    pub async fn get_buffer(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock().await;
        buffers.pop().unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    pub async fn return_buffer(&self, mut buffer: Vec<u8>) {
        let mut buffers = self.buffers.lock().await;
        if buffers.len() < self.max_buffers {
            buffer.clear();
            buffer.resize(self.buffer_size, 0);
            buffers.push(buffer);
        }
    }
}

/// Query router trait for handling DNS queries
#[async_trait::async_trait]
pub trait QueryRouter: Send + Sync {
    async fn route_query(&self, query: DnsQuery, client_addr: SocketAddr) -> DnsResult<DnsResponse>;
}

/// TCP DNS handler for large responses and zone transfers
pub struct TcpDnsHandler {
    query_router: Arc<dyn QueryRouter>,
    zone_manager: Arc<dyn ZoneManager>,
    max_connections: usize,
    connection_timeout: std::time::Duration,
}

impl TcpDnsHandler {
    /// Create a new TCP DNS handler
    pub fn new(query_router: Arc<dyn QueryRouter>, zone_manager: Arc<dyn ZoneManager>) -> Self {
        Self {
            query_router,
            zone_manager,
            max_connections: 1000,
            connection_timeout: std::time::Duration::from_secs(30),
        }
    }
}

/// Zone manager trait for handling zone operations
#[async_trait::async_trait]
pub trait ZoneManager: Send + Sync {
    async fn get_zone_data(&self, zone_hash: u64, since_version: u64) -> DnsResult<ZoneData>;
    async fn apply_update(&self, update: DynamicUpdate) -> DnsResult<UpdateResult>;
    async fn get_zone_version(&self, zone_hash: u64) -> DnsResult<u64>;
}

/// Zone data response
#[derive(Debug, Clone)]
pub struct ZoneData {
    pub data: Vec<u8>,
    pub version: u64,
    pub is_delta: bool,
}

/// Update result
#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub success: bool,
    pub new_version: u64,
    pub error_message: Option<String>,
}

#[async_trait::async_trait]
impl DnsProtocolHandler for TcpDnsHandler {
    async fn handle_query(&self, query: DnsQuery, client_addr: SocketAddr) -> DnsResult<DnsResponse> {
        self.query_router.route_query(query, client_addr).await
    }

    async fn start_listener(&self, bind_addr: SocketAddr) -> DnsResult<()> {
        tracing::info!("Starting TCP DNS server on {}", bind_addr);
        
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| DnsError::network_error(e.to_string()))?;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_connections));
        
        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    let permit = semaphore.clone().acquire_owned().await
                        .map_err(|e| DnsError::ResourceExhausted { resource: format!("Connection semaphore: {}", e) })?;
                    let router = self.query_router.clone();
                    let zone_manager = self.zone_manager.clone();
                    let timeout = self.connection_timeout;
                    
                    tokio::spawn(async move {
                        let _permit = permit; // Keep permit alive for connection duration
                        
                        if let Err(e) = tokio::time::timeout(
                            timeout,
                            Self::handle_connection(stream, client_addr, router, zone_manager)
                        ).await {
                            tracing::warn!("TCP connection from {} timed out", client_addr);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept TCP connection: {}", e);
                }
            }
        }
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Tcp
    }

    async fn handle_zone_sync(&self, sync_request: ZoneSyncRequest, _client_addr: SocketAddr) -> DnsResult<ZoneSyncResponse> {
        let zone_data = self.zone_manager.get_zone_data(sync_request.zone_hash, sync_request.last_known_version).await?;
        
        Ok(ZoneSyncResponse {
            zone_data: zone_data.data,
            version: zone_data.version,
            delta: zone_data.is_delta,
            compression: sync_request.compression,
        })
    }

    async fn handle_dynamic_update(&self, update: DynamicUpdate, _client_addr: SocketAddr) -> DnsResult<UpdateResponse> {
        let result = self.zone_manager.apply_update(update).await?;
        
        Ok(UpdateResponse {
            success: result.success,
            new_version: result.new_version,
            error_message: result.error_message,
        })
    }

    async fn handle_zone_notify(&self, notify: ZoneNotify, _client_addr: SocketAddr) -> DnsResult<NotifyResponse> {
        let current_version = self.zone_manager.get_zone_version(notify.zone_hash).await?;
        
        Ok(NotifyResponse {
            acknowledged: true,
            current_version,
        })
    }
}

impl TcpDnsHandler {
    /// Handle a single TCP connection
    async fn handle_connection(
        mut stream: TcpStream,
        client_addr: SocketAddr,
        router: Arc<dyn QueryRouter>,
        zone_manager: Arc<dyn ZoneManager>,
    ) -> DnsResult<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        loop {
            // Read message length (2 bytes, network byte order)
            let mut length_buf = [0u8; 2];
            match stream.read_exact(&mut length_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Client closed connection
                    break;
                }
                Err(e) => return Err(DnsError::network_error(e.to_string())),
            }
            
            let message_length = u16::from_be_bytes(length_buf) as usize;
            if message_length == 0 || message_length > 65535 {
                return Err(DnsError::InvalidPacket { message: "Invalid TCP message length".to_string() });
            }
            
            // Read message data
            let mut message_buf = vec![0u8; message_length];
            stream.read_exact(&mut message_buf).await.map_err(|e| DnsError::network_error(e.to_string()))?;
            
            // Check if this is a zone sync request (custom protocol)
            if message_buf.len() > 8 && &message_buf[0..4] == b"ZSYN" {
                let response = Self::handle_zone_sync_tcp(&message_buf[4..], client_addr, zone_manager.clone()).await?;
                
                // Send response with length prefix
                let response_len = response.len() as u16;
                stream.write_all(&response_len.to_be_bytes()).await.map_err(|e| DnsError::network_error(e.to_string()))?;
                stream.write_all(&response).await.map_err(|e| DnsError::network_error(e.to_string()))?;
            } else {
                // Standard DNS query
                let mut query = DnsQuery::from_bytes(&message_buf)?;
                query.client_addr = client_addr.ip();
                let response = router.route_query(query, client_addr).await?;
                let response_bytes = response.to_bytes()?;
                
                // Send response with length prefix
                let response_len = response_bytes.len() as u16;
                stream.write_all(&response_len.to_be_bytes()).await.map_err(|e| DnsError::network_error(e.to_string()))?;
                stream.write_all(&response_bytes).await.map_err(|e| DnsError::network_error(e.to_string()))?;
            }
        }
        
        Ok(())
    }

    /// Handle zone synchronization over TCP
    async fn handle_zone_sync_tcp(
        data: &[u8],
        _client_addr: SocketAddr,
        zone_manager: Arc<dyn ZoneManager>,
    ) -> DnsResult<Vec<u8>> {
        // Parse zone sync request
        let sync_request: ZoneSyncRequest = bincode::deserialize(data)
            .map_err(|e| DnsError::SerializationError { message: e.to_string() })?;
        
        // Get zone data
        let zone_data = zone_manager.get_zone_data(sync_request.zone_hash, sync_request.last_known_version).await?;
        
        let response = ZoneSyncResponse {
            zone_data: zone_data.data,
            version: zone_data.version,
            delta: zone_data.is_delta,
            compression: CompressionType::None,
        };
        
        // Serialize response
        Ok(bincode::serialize(&response)
            .map_err(|e| DnsError::SerializationError { message: e.to_string() })?)
    }
}

// DoH Handler (DNS over HTTPS)
#[cfg(feature = "doh")]
pub struct DohHandler {
    query_router: Arc<dyn QueryRouter>,
}

#[cfg(feature = "doh")]
impl DohHandler {
    pub fn new(query_router: Arc<dyn QueryRouter>) -> Self {
        Self { query_router }
    }
}

#[cfg(feature = "doh")]
#[async_trait::async_trait]
impl DnsProtocolHandler for DohHandler {
    async fn handle_query(&self, query: DnsQuery, client_addr: SocketAddr) -> DnsResult<DnsResponse> {
        self.query_router.route_query(query, client_addr).await
    }

    async fn start_listener(&self, bind_addr: SocketAddr) -> DnsResult<()> {
        tracing::info!("Starting DoH server on {}", bind_addr);
        // DoH implementation would go here - requires hyper HTTP/2 server
        Err(DnsError::NotImplemented { feature: "DoH server".to_string() })
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::DoH
    }

    async fn handle_zone_sync(&self, _sync_request: ZoneSyncRequest, _client_addr: SocketAddr) -> DnsResult<ZoneSyncResponse> {
        Err(DnsError::NotImplemented { feature: "Zone sync not supported over DoH".to_string() })
    }

    async fn handle_dynamic_update(&self, _update: DynamicUpdate, _client_addr: SocketAddr) -> DnsResult<UpdateResponse> {
        Err(DnsError::NotImplemented { feature: "Dynamic updates not supported over DoH".to_string() })
    }

    async fn handle_zone_notify(&self, _notify: ZoneNotify, _client_addr: SocketAddr) -> DnsResult<NotifyResponse> {
        Err(DnsError::NotImplemented { feature: "Zone notify not supported over DoH".to_string() })
    }
}

// DoT Handler (DNS over TLS)
#[cfg(feature = "dot")]
pub struct DotHandler {
    query_router: Arc<dyn QueryRouter>,
    zone_manager: Arc<dyn ZoneManager>,
}

#[cfg(feature = "dot")]
impl DotHandler {
    pub fn new(query_router: Arc<dyn QueryRouter>, zone_manager: Arc<dyn ZoneManager>) -> Self {
        Self { query_router, zone_manager }
    }
}

#[cfg(feature = "dot")]
#[async_trait::async_trait]
impl DnsProtocolHandler for DotHandler {
    async fn handle_query(&self, query: DnsQuery, client_addr: SocketAddr) -> DnsResult<DnsResponse> {
        self.query_router.route_query(query, client_addr).await
    }

    async fn start_listener(&self, bind_addr: SocketAddr) -> DnsResult<()> {
        tracing::info!("Starting DoT server on {}", bind_addr);
        // DoT implementation would go here - requires TLS acceptor
        Err(DnsError::NotImplemented { feature: "DoT server".to_string() })
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::DoT
    }

    async fn handle_zone_sync(&self, sync_request: ZoneSyncRequest, _client_addr: SocketAddr) -> DnsResult<ZoneSyncResponse> {
        let zone_data = self.zone_manager.get_zone_data(sync_request.zone_hash, sync_request.last_known_version).await?;
        
        Ok(ZoneSyncResponse {
            zone_data: zone_data.data,
            version: zone_data.version,
            delta: zone_data.is_delta,
            compression: sync_request.compression,
        })
    }

    async fn handle_dynamic_update(&self, update: DynamicUpdate, _client_addr: SocketAddr) -> DnsResult<UpdateResponse> {
        let result = self.zone_manager.apply_update(update).await?;
        
        Ok(UpdateResponse {
            success: result.success,
            new_version: result.new_version,
            error_message: result.error_message,
        })
    }

    async fn handle_zone_notify(&self, notify: ZoneNotify, _client_addr: SocketAddr) -> DnsResult<NotifyResponse> {
        let current_version = self.zone_manager.get_zone_version(notify.zone_hash).await?;
        
        Ok(NotifyResponse {
            acknowledged: true,
            current_version,
        })
    }
}

// DoQ Handler (DNS over QUIC)
#[cfg(feature = "doq")]
pub struct DoqHandler {
    query_router: Arc<dyn QueryRouter>,
    zone_manager: Arc<dyn ZoneManager>,
}

#[cfg(feature = "doq")]
impl DoqHandler {
    pub fn new(query_router: Arc<dyn QueryRouter>, zone_manager: Arc<dyn ZoneManager>) -> Self {
        Self { query_router, zone_manager }
    }
}

#[cfg(feature = "doq")]
#[async_trait::async_trait]
impl DnsProtocolHandler for DoqHandler {
    async fn handle_query(&self, query: DnsQuery, client_addr: SocketAddr) -> DnsResult<DnsResponse> {
        self.query_router.route_query(query, client_addr).await
    }

    async fn start_listener(&self, bind_addr: SocketAddr) -> DnsResult<()> {
        tracing::info!("Starting DoQ server on {}", bind_addr);
        // DoQ implementation would go here - requires QUIC endpoint
        Err(DnsError::NotImplemented { feature: "DoQ server".to_string() })
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::DoQ
    }

    async fn handle_zone_sync(&self, sync_request: ZoneSyncRequest, _client_addr: SocketAddr) -> DnsResult<ZoneSyncResponse> {
        let zone_data = self.zone_manager.get_zone_data(sync_request.zone_hash, sync_request.last_known_version).await?;
        
        Ok(ZoneSyncResponse {
            zone_data: zone_data.data,
            version: zone_data.version,
            delta: zone_data.is_delta,
            compression: sync_request.compression,
        })
    }

    async fn handle_dynamic_update(&self, update: DynamicUpdate, _client_addr: SocketAddr) -> DnsResult<UpdateResponse> {
        let result = self.zone_manager.apply_update(update).await?;
        
        Ok(UpdateResponse {
            success: result.success,
            new_version: result.new_version,
            error_message: result.error_message,
        })
    }

    async fn handle_zone_notify(&self, notify: ZoneNotify, _client_addr: SocketAddr) -> DnsResult<NotifyResponse> {
        let current_version = self.zone_manager.get_zone_version(notify.zone_hash).await?;
        
        Ok(NotifyResponse {
            acknowledged: true,
            current_version,
        })
    }
}