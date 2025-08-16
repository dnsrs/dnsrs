use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dns_core::{global_metrics, ProtocolType, ResponseCode};
use dns_monitoring::{PrometheusExporter, PrometheusConfig};
use std::time::Duration;

fn benchmark_atomic_metrics(c: &mut Criterion) {
    let metrics = global_metrics();
    
    c.bench_function("record_query", |b| {
        b.iter(|| {
            metrics.record_query(
                black_box(1_000_000), // 1ms in nanoseconds
                black_box(ProtocolType::Udp),
            );
        })
    });
    
    c.bench_function("record_response", |b| {
        b.iter(|| {
            metrics.record_response(black_box(ResponseCode::NoError));
        })
    });
    
    c.bench_function("record_cache_hit", |b| {
        b.iter(|| {
            metrics.record_cache_hit();
        })
    });
    
    c.bench_function("record_cache_miss", |b| {
        b.iter(|| {
            metrics.record_cache_miss();
        })
    });
    
    c.bench_function("record_blocked_query", |b| {
        b.iter(|| {
            metrics.record_blocked_query();
        })
    });
    
    c.bench_function("metrics_snapshot", |b| {
        b.iter(|| {
            black_box(metrics.snapshot());
        })
    });
}

fn benchmark_prometheus_exporter(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("prometheus_gather", |b| {
        let config = PrometheusConfig::default();
        let exporter = PrometheusExporter::new(config).unwrap();
        
        b.iter(|| {
            black_box(exporter.gather().unwrap());
        })
    });
    
    c.bench_function("prometheus_record_query", |b| {
        let config = PrometheusConfig::default();
        let exporter = PrometheusExporter::new(config).unwrap();
        
        b.iter(|| {
            exporter.record_query(
                black_box(Duration::from_millis(1)),
                black_box(Some(512)),
            );
        })
    });
}

fn benchmark_concurrent_metrics(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("concurrent_metrics_1_thread", |b| {
        b.iter(|| {
            rt.block_on(async {
                let metrics = global_metrics();
                for _ in 0..1000 {
                    metrics.record_query(1_000_000, ProtocolType::Udp);
                    metrics.record_response(ResponseCode::NoError);
                    metrics.record_cache_hit();
                }
            });
        })
    });
    
    c.bench_function("concurrent_metrics_4_threads", |b| {
        b.iter(|| {
            rt.block_on(async {
                let handles: Vec<_> = (0..4).map(|_| {
                    tokio::spawn(async {
                        let metrics = global_metrics();
                        for _ in 0..250 {
                            metrics.record_query(1_000_000, ProtocolType::Udp);
                            metrics.record_response(ResponseCode::NoError);
                            metrics.record_cache_hit();
                        }
                    })
                }).collect();
                
                for handle in handles {
                    handle.await.unwrap();
                }
            });
        })
    });
    
    c.bench_function("concurrent_metrics_8_threads", |b| {
        b.iter(|| {
            rt.block_on(async {
                let handles: Vec<_> = (0..8).map(|_| {
                    tokio::spawn(async {
                        let metrics = global_metrics();
                        for _ in 0..125 {
                            metrics.record_query(1_000_000, ProtocolType::Udp);
                            metrics.record_response(ResponseCode::NoError);
                            metrics.record_cache_hit();
                        }
                    })
                }).collect();
                
                for handle in handles {
                    handle.await.unwrap();
                }
            });
        })
    });
}

criterion_group!(
    benches,
    benchmark_atomic_metrics,
    benchmark_prometheus_exporter,
    benchmark_concurrent_metrics
);
criterion_main!(benches);