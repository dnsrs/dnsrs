//! Benchmarks for rate limiting performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dns_security::{AtomicRateLimiter, RateLimitConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::runtime::Runtime;

fn bench_rate_limiter_single_client(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let config = RateLimitConfig {
        max_tokens: 1000,
        refill_rate: 100,
        global_rate_limit: None,
        cleanup_interval: 300,
        max_clients: 100000,
    };
    
    let rate_limiter = Arc::new(AtomicRateLimiter::new(config).unwrap());
    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    c.bench_function("rate_limiter_single_client", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(rate_limiter.check_rate_limit(client_ip).await.unwrap())
        })
    });
}

fn bench_rate_limiter_multiple_clients(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let config = RateLimitConfig {
        max_tokens: 100,
        refill_rate: 10,
        global_rate_limit: None,
        cleanup_interval: 300,
        max_clients: 100000,
    };
    
    let rate_limiter = Arc::new(AtomicRateLimiter::new(config).unwrap());

    for client_count in [10, 100, 1000, 10000].iter() {
        c.bench_with_input(
            BenchmarkId::new("rate_limiter_multiple_clients", client_count),
            client_count,
            |b, &client_count| {
                b.to_async(&rt).iter(|| async {
                    let mut results = Vec::new();
                    
                    for i in 0..client_count {
                        let ip = IpAddr::V4(Ipv4Addr::new(
                            10,
                            (i >> 16) as u8,
                            (i >> 8) as u8,
                            i as u8,
                        ));
                        
                        let result = rate_limiter.check_rate_limit(ip).await.unwrap();
                        results.push(result);
                    }
                    
                    black_box(results)
                })
            },
        );
    }
}

fn bench_rate_limiter_concurrent(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let config = RateLimitConfig {
        max_tokens: 1000,
        refill_rate: 100,
        global_rate_limit: None,
        cleanup_interval: 300,
        max_clients: 100000,
    };
    
    let rate_limiter = Arc::new(AtomicRateLimiter::new(config).unwrap());

    for thread_count in [1, 2, 4, 8, 16].iter() {
        c.bench_with_input(
            BenchmarkId::new("rate_limiter_concurrent", thread_count),
            thread_count,
            |b, &thread_count| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();
                    
                    for t in 0..thread_count {
                        let limiter = rate_limiter.clone();
                        let handle = tokio::spawn(async move {
                            let mut results = Vec::new();
                            
                            for i in 0..100 {
                                let ip = IpAddr::V4(Ipv4Addr::new(
                                    10,
                                    t as u8,
                                    (i >> 8) as u8,
                                    i as u8,
                                ));
                                
                                let result = limiter.check_rate_limit(ip).await.unwrap();
                                results.push(result);
                            }
                            
                            results
                        });
                        handles.push(handle);
                    }
                    
                    let mut all_results = Vec::new();
                    for handle in handles {
                        let results = handle.await.unwrap();
                        all_results.extend(results);
                    }
                    
                    black_box(all_results)
                })
            },
        );
    }
}

fn bench_token_bucket_operations(c: &mut Criterion) {
    use dns_security::AtomicTokenBucket;
    
    let bucket = AtomicTokenBucket::new(1000, 100);

    c.bench_function("token_bucket_check_and_consume", |b| {
        b.iter(|| {
            black_box(bucket.check_and_consume(1))
        })
    });

    c.bench_function("token_bucket_current_tokens", |b| {
        b.iter(|| {
            black_box(bucket.current_tokens())
        })
    });
}

fn bench_rate_limiter_memory_usage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let config = RateLimitConfig {
        max_tokens: 100,
        refill_rate: 10,
        global_rate_limit: None,
        cleanup_interval: 300,
        max_clients: 100000,
    };

    c.bench_function("rate_limiter_memory_pressure", |b| {
        b.to_async(&rt).iter(|| async {
            let rate_limiter = AtomicRateLimiter::new(config.clone()).unwrap();
            
            // Create many clients to test memory usage
            for i in 0..10000 {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    (i >> 24) as u8,
                    (i >> 16) as u8,
                    (i >> 8) as u8,
                    i as u8,
                ));
                
                let _ = rate_limiter.check_rate_limit(ip).await.unwrap();
            }
            
            black_box(rate_limiter)
        })
    });
}

criterion_group!(
    benches,
    bench_rate_limiter_single_client,
    bench_rate_limiter_multiple_clients,
    bench_rate_limiter_concurrent,
    bench_token_bucket_operations,
    bench_rate_limiter_memory_usage
);

criterion_main!(benches);