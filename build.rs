use std::process::Command;

fn main() {
    // Generate FlatBuffers code
    let output = Command::new("flatc")
        .args(&[
            "--rust",
            "--gen-mutable",
            "--gen-object-api",
            "--filename-suffix", "",
            "-o", "src/generated",
            "schemas/dns.fbs"
        ])
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                println!("cargo:warning=FlatBuffers generation failed: {}", 
                    String::from_utf8_lossy(&output.stderr));
                println!("cargo:warning=Make sure flatc is installed and in PATH");
            }
        }
        Err(e) => {
            println!("cargo:warning=Failed to run flatc: {}", e);
            println!("cargo:warning=FlatBuffers code generation skipped");
        }
    }

    // Re-run if schema changes
    println!("cargo:rerun-if-changed=schemas/dns.fbs");
}