use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let schema_path = Path::new("../../schemas/dns.fbs");
    
    // Generate FlatBuffers code using flatc command
    let output = Command::new("flatc")
        .args(&["--rust", "-o", &out_dir])
        .arg(schema_path)
        .output();
    
    match output {
        Ok(output) => {
            if !output.status.success() {
                panic!("flatc failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(e) => {
            // If flatc is not available, create a minimal generated file
            eprintln!("Warning: flatc not found ({}), creating minimal generated code", e);
            
            let generated_path = Path::new(&out_dir).join("dns_generated.rs");
            std::fs::write(&generated_path, r#"
// Minimal generated FlatBuffers code (flatc not available)
pub mod dns {
    pub mod storage {
        // Placeholder types - replace with actual generated code
        pub struct DnsPacket;
        pub struct DnsHeader;
        pub struct Zone;
        
        impl DnsPacket {
            pub fn create(_builder: &mut flatbuffers::FlatBufferBuilder, _args: &DnsPacketArgs) -> Self {
                Self
            }
        }
        
        impl DnsHeader {
            pub fn create(_builder: &mut flatbuffers::FlatBufferBuilder, _args: &DnsHeaderArgs) -> Self {
                Self
            }
        }
        
        pub struct DnsPacketArgs<'a> {
            pub raw_data: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, u8>>>,
            pub parsed_header: Option<DnsHeader>,
            pub question_offset: u16,
            pub answer_offset: u16,
            pub authority_offset: u16,
            pub additional_offset: u16,
            pub packet_hash: u64,
            pub query_hash: u64,
            pub is_response: bool,
            pub is_authoritative: bool,
            pub is_truncated: bool,
            pub can_serve_from_cache: bool,
            pub requires_dnssec: bool,
        }
        
        pub struct DnsHeaderArgs {
            pub id: u16,
            pub flags: u16,
            pub qdcount: u16,
            pub ancount: u16,
            pub nscount: u16,
            pub arcount: u16,
        }
    }
}
"#).expect("Failed to write generated code");
        }
    }
    
    println!("cargo:rerun-if-changed=../../schemas/dns.fbs");
}