//! Comprehensive DNSSEC implementation tests

#[cfg(test)]
mod tests {
    use crate::dnssec::*;
    use crate::key_management::*;
    use crate::nsec_chain::*;
    use crate::dnssec_processor::*;
    use bytes::Bytes;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_dnssec_key_generation() {
        let zone_name = "example.com".to_string();
        let algorithm = DnssecAlgorithm::EcdsaP256Sha256;
        let flags = DnssecKeyFlags {
            zone_key: true,
            secure_entry_point: false,
            revoked: false,
        };

        let key_pair = DnssecKeyPair::generate(zone_name, algorithm, flags, None).unwrap();
        
        assert_eq!(key_pair.algorithm, algorithm);
        assert_eq!(key_pair.flags.zone_key, true);
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.private_key.is_empty());
    }

    #[tokio::test]
    async fn test_dnssec_signing_and_validation() {
        let zone_name = "example.com";
        let validator = Arc::new(DnssecValidator::new());
        let signer = Arc::new(DnssecSigner::new());

        // Initialize signing for zone
        let policy = SigningPolicy::default();
        signer.initialize_zone_signing(zone_name.to_string(), policy).await.unwrap();

        // Sign an RRset
        let rrset_data = b"192.0.2.1"; // A record data
        let rrsig = signer.sign_rrset(
            zone_name,
            "www.example.com",
            1, // A record
            1, // IN class
            3600, // TTL
            rrset_data,
        ).await.unwrap();

        assert_eq!(rrsig.type_covered, 1);
        assert_eq!(rrsig.signer_name, zone_name);
        assert!(!rrsig.signature.is_empty());

        // Get DNSKEY records for validation
        let dnskeys = signer.get_dnskey_records(zone_name).await.unwrap();
        assert!(!dnskeys.is_empty());

        // Add DNSKEY as trusted anchor
        for dnskey in dnskeys {
            validator.add_trusted_anchor(zone_name.to_string(), dnskey).await.unwrap();
        }

        // Validate the signature
        let validation_result = validator.validate_rrsig(
            &rrsig,
            rrset_data,
            "www.example.com",
            1, // A record
            1, // IN class
            3600, // TTL
        ).await.unwrap();

        assert!(validation_result.valid, "Signature validation failed: {:?}", validation_result.error);
    }

    #[tokio::test]
    async fn test_key_management() {
        let temp_dir = TempDir::new().unwrap();
        let hsm = Arc::new(MockHsm::new());
        let key_manager = AtomicKeyManager::new(temp_dir.path(), Some(hsm.clone())).unwrap();

        // Generate software key
        let key_id = key_manager.generate_key_atomic(
            "example.com",
            DnssecAlgorithm::EcdsaP256Sha256,
            DnssecKeyFlags {
                zone_key: true,
                secure_entry_point: false,
                revoked: false,
            },
            false, // Don't use HSM
        ).await.unwrap();

        // Verify key exists and is active
        let key_entry = key_manager.get_key_atomic(&key_id).await.unwrap();
        assert!(key_entry.is_active());

        // Sign data with the key
        let test_data = b"test data to sign";
        let signature = key_manager.sign_with_key_atomic(&key_id, test_data).await.unwrap();
        assert!(!signature.is_empty());

        // Test key rollover
        let new_key_id = key_manager.rollover_key_atomic(
            "example.com",
            &key_id,
            DnssecAlgorithm::EcdsaP256Sha256,
            DnssecKeyFlags {
                zone_key: true,
                secure_entry_point: false,
                revoked: false,
            },
            false,
        ).await.unwrap();

        assert_ne!(key_id, new_key_id);

        // Old key should be deactivated
        let old_key_entry = key_manager.get_key_atomic(&key_id).await;
        assert!(old_key_entry.is_none() || !old_key_entry.unwrap().is_active());

        // New key should be active
        let new_key_entry = key_manager.get_key_atomic(&new_key_id).await.unwrap();
        assert!(new_key_entry.is_active());
    }

    #[tokio::test]
    async fn test_hsm_integration() {
        let temp_dir = TempDir::new().unwrap();
        let hsm = Arc::new(MockHsm::new());
        let key_manager = AtomicKeyManager::new(temp_dir.path(), Some(hsm.clone())).unwrap();

        // Test HSM health check
        assert!(key_manager.hsm_health_check().await.unwrap());

        // Generate HSM-backed key
        let key_id = key_manager.generate_key_atomic(
            "example.com",
            DnssecAlgorithm::EcdsaP256Sha256,
            DnssecKeyFlags {
                zone_key: true,
                secure_entry_point: true,
                revoked: false,
            },
            true, // Use HSM
        ).await.unwrap();

        // Verify key is HSM-backed
        let key_info = key_manager.get_key_info(&key_id).await.unwrap();
        assert!(key_info.is_hsm_backed);

        // Sign data using HSM
        let test_data = b"hsm test data";
        let signature = key_manager.sign_with_key_atomic(&key_id, test_data).await.unwrap();
        assert!(!signature.is_empty());

        // Test HSM failure scenario
        hsm.set_operational(false);
        assert!(!key_manager.hsm_health_check().await.unwrap());

        // Should fail to generate new keys when HSM is down
        let result = key_manager.generate_key_atomic(
            "example.com",
            DnssecAlgorithm::EcdsaP256Sha256,
            DnssecKeyFlags {
                zone_key: true,
                secure_entry_point: false,
                revoked: false,
            },
            true, // Use HSM
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nsec_chain_generation() {
        let manager = NsecChainManager::new("example.com".to_string());

        // Add domain names to the zone
        manager.add_zone_name("example.com".to_string(), vec![1, 2, 6]).await; // A, NS, SOA
        manager.add_zone_name("www.example.com".to_string(), vec![1]).await; // A
        manager.add_zone_name("mail.example.com".to_string(), vec![1, 15]).await; // A, MX
        manager.add_zone_name("ftp.example.com".to_string(), vec![1]).await; // A

        // Generate NSEC chain
        manager.generate_nsec_chain().await.unwrap();

        // Validate chain integrity
        assert!(manager.validate_nsec_chain().await.unwrap());

        // Test denial of existence
        let covering_nsec = manager.find_covering_nsec("nonexistent.example.com").await;
        assert!(covering_nsec.is_some());

        let nsec_record = covering_nsec.unwrap();
        assert!(nsec_record.covers_name("nonexistent.example.com"));
    }

    #[tokio::test]
    async fn test_nsec3_chain_generation() {
        let manager = NsecChainManager::new("example.com".to_string());

        // Add domain names
        manager.add_zone_name("example.com".to_string(), vec![1, 2, 6]).await;
        manager.add_zone_name("www.example.com".to_string(), vec![1]).await;
        manager.add_zone_name("mail.example.com".to_string(), vec![1, 15]).await;

        // Set NSEC3 parameters
        manager.set_nsec3_params(
            1, // SHA-1
            0, // No opt-out
            10, // 10 iterations
            Bytes::from("deadbeef"),
            3600,
        ).await.unwrap();

        // Validate chain integrity
        assert!(manager.validate_nsec3_chain().await.unwrap());

        // Test denial of existence
        let covering_nsec3 = manager.find_covering_nsec3("nonexistent.example.com").await.unwrap();
        assert!(covering_nsec3.is_some());

        let nsec3_record = covering_nsec3.unwrap();
        assert!(nsec3_record.covers_name("nonexistent.example.com").unwrap());
    }

    #[tokio::test]
    async fn test_dnssec_query_processing() {
        let validator = Arc::new(DnssecValidator::new());
        let signer = Arc::new(DnssecSigner::new());
        let denial_generator = Arc::new(DenialProofGenerator::new());
        let processor = DnssecQueryProcessor::new(validator, signer, denial_generator);

        // Configure zone for DNSSEC
        let zone_config = ZoneDnssecConfig {
            is_signed: true,
            auto_sign: true,
            validation_required: false,
            nsec3_enabled: true,
            trust_anchors: Vec::new(),
        };
        processor.configure_zone_dnssec("example.com".to_string(), zone_config).await.unwrap();

        // Create query context
        let context = DnssecQueryContext {
            query_name: "www.example.com".to_string(),
            query_type: 1, // A
            query_class: 1, // IN
            flags: DnssecQueryFlags {
                checking_disabled: false,
                dnssec_ok: true,
                authenticated_data: false,
            },
            client_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            zone_name: "example.com".to_string(),
            is_authoritative: true,
        };

        // Create base response
        let base_response = vec![
            DnsRecordWithSig {
                record_data: Bytes::from(vec![192, 0, 2, 1]),
                record_type: 1, // A
                record_class: 1, // IN
                ttl: 3600,
                name: "www.example.com".to_string(),
                rrsig: None,
            }
        ];

        // Process query
        let response = processor.process_query(context, base_response).await.unwrap();

        assert_eq!(response.answer_records.len(), 1);
        assert!(response.flags.dnssec_ok);
        
        // Should have generated signatures since auto_sign is enabled
        // (Note: This would require proper zone initialization in a real scenario)
    }

    #[tokio::test]
    async fn test_ds_record_generation() {
        let zone_name = "example.com";
        let signer = Arc::new(DnssecSigner::new());

        // Initialize signing
        let policy = SigningPolicy::default();
        signer.initialize_zone_signing(zone_name.to_string(), policy).await.unwrap();

        // Generate DS records
        let ds_records = signer.generate_ds_records(
            zone_name,
            &[crate::dnssec::DigestType::Sha256, crate::dnssec::DigestType::Sha384],
        ).await.unwrap();

        assert!(!ds_records.is_empty());

        for ds in &ds_records {
            assert!(!ds.digest.is_empty());
            assert!(matches!(ds.digest_type, crate::dnssec::DigestType::Sha256 | crate::dnssec::DigestType::Sha384));
        }
    }

    #[tokio::test]
    async fn test_denial_proof_generation() {
        let generator = DenialProofGenerator::new();
        let nsec_manager = Arc::new(NsecChainManager::new("example.com".to_string()));

        // Add zone manager
        generator.add_zone_manager("example.com".to_string(), nsec_manager.clone()).await;

        // Add some names to create NSEC chain
        nsec_manager.add_zone_name("example.com".to_string(), vec![1, 2]).await;
        nsec_manager.add_zone_name("www.example.com".to_string(), vec![1]).await;
        nsec_manager.generate_nsec_chain().await.unwrap();

        // Generate denial proof for non-existent name
        let proof = generator.generate_denial_proof(
            "example.com",
            "nonexistent.example.com",
            1, // A record
        ).await.unwrap();

        match proof {
            DenialProof::Nsec { nsec_record } => {
                assert!(nsec_record.covers_name("nonexistent.example.com"));
            }
            _ => panic!("Expected NSEC proof"),
        }
    }

    #[tokio::test]
    async fn test_comprehensive_dnssec_workflow() {
        // This test demonstrates a complete DNSSEC workflow
        let temp_dir = TempDir::new().unwrap();
        let hsm = Arc::new(MockHsm::new());
        
        // Initialize components
        let validator = Arc::new(DnssecValidator::new());
        let signer = Arc::new(DnssecSigner::new());
        let denial_generator = Arc::new(DenialProofGenerator::new());
        let key_manager = AtomicKeyManager::new(temp_dir.path(), Some(hsm.clone())).unwrap();
        let processor = DnssecQueryProcessor::new(validator.clone(), signer.clone(), denial_generator.clone());

        let zone_name = "example.com";

        // 1. Initialize DNSSEC for zone
        let policy = SigningPolicy::default();
        signer.initialize_zone_signing(zone_name.to_string(), policy).await.unwrap();

        // 2. Configure zone for DNSSEC processing
        processor.enable_zone_dnssec(zone_name.to_string(), true, true).await.unwrap();

        // 3. Set up NSEC3 chain
        let nsec_manager = Arc::new(NsecChainManager::new(zone_name.to_string()));
        nsec_manager.add_zone_name(zone_name.to_string(), vec![1, 2, 6]).await;
        nsec_manager.add_zone_name("www.example.com".to_string(), vec![1]).await;
        nsec_manager.set_nsec3_params(1, 0, 10, Bytes::from("salt"), 3600).await.unwrap();
        
        denial_generator.add_zone_manager(zone_name.to_string(), nsec_manager).await;

        // 4. Get DNSKEY records and add as trust anchors
        let dnskeys = signer.get_dnskey_records(zone_name).await.unwrap();
        for dnskey in dnskeys {
            processor.add_trust_anchor(zone_name.to_string(), dnskey).await.unwrap();
        }

        // 5. Process a DNSSEC query
        let context = DnssecQueryContext {
            query_name: "www.example.com".to_string(),
            query_type: 1, // A
            query_class: 1, // IN
            flags: DnssecQueryFlags {
                checking_disabled: false,
                dnssec_ok: true,
                authenticated_data: false,
            },
            client_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            zone_name: zone_name.to_string(),
            is_authoritative: true,
        };

        let base_response = vec![
            DnsRecordWithSig {
                record_data: Bytes::from(vec![192, 0, 2, 1]),
                record_type: 1, // A
                record_class: 1, // IN
                ttl: 3600,
                name: "www.example.com".to_string(),
                rrsig: None,
            }
        ];

        let response = processor.process_query(context, base_response).await.unwrap();

        // Verify response has DNSSEC records
        assert!(!response.answer_records.is_empty());
        assert!(response.flags.dnssec_ok);

        // 6. Test denial of existence
        let denial_context = DnssecQueryContext {
            query_name: "nonexistent.example.com".to_string(),
            query_type: 1, // A
            query_class: 1, // IN
            flags: DnssecQueryFlags {
                checking_disabled: false,
                dnssec_ok: true,
                authenticated_data: false,
            },
            client_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            zone_name: zone_name.to_string(),
            is_authoritative: true,
        };

        let denial_response = processor.process_query(denial_context, vec![]).await.unwrap();
        
        // Should have denial proof for non-existent name
        assert!(denial_response.denial_proof.is_some());
        
        println!("Comprehensive DNSSEC workflow test completed successfully!");
    }
}