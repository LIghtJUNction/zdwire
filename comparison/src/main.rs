use std::hint::black_box;
use std::time::{Duration, Instant};

use zdwire_comparison::{
    domain_raw, domain_snapshot, domain_specialized, domain_typed, encode, fixtures, zdwire_raw,
    zdwire_snapshot, zdwire_typed,
};

fn batch<F: FnMut() -> u64>(count: u64, run: &mut F) -> f64 {
    let start = Instant::now();
    for _ in 0..count {
        black_box(run());
    }
    start.elapsed().as_secs_f64() * 1e9 / count as f64
}

fn calibrate<F: FnMut() -> u64>(target: Duration, run: &mut F) -> u64 {
    let mut count = 128;
    loop {
        let nanos = batch(count, run);
        if nanos * count as f64 >= target.as_nanos() as f64 / 4.0 || count >= 1 << 27 {
            return ((target.as_nanos() as f64 / nanos.max(0.1)) as u64).clamp(64, 1 << 29);
        }
        count *= 4;
    }
}

fn measure<A: FnMut() -> u64, B: FnMut() -> u64>(
    mode: &str,
    name: &str,
    bytes: usize,
    mut zd: A,
    mut domain: B,
    target: Duration,
    samples: usize,
) {
    let zcount = calibrate(target, &mut zd);
    let dcount = calibrate(target, &mut domain);
    let mut zs = Vec::with_capacity(samples);
    let mut ds = Vec::with_capacity(samples);
    for round in 0..samples {
        if round % 2 == 0 {
            zs.push(batch(zcount, &mut zd));
            ds.push(batch(dcount, &mut domain));
        } else {
            ds.push(batch(dcount, &mut domain));
            zs.push(batch(zcount, &mut zd));
        }
    }
    zs.sort_by(f64::total_cmp);
    ds.sort_by(f64::total_cmp);
    let z = zs[samples / 2];
    let d = ds[samples / 2];
    let zi = (zs[samples * 3 / 4] - zs[samples / 4]) / z * 100.0;
    let di = (ds[samples * 3 / 4] - ds[samples / 4]) / d * 100.0;
    println!(
        "{mode},{name},{bytes},{z:.3},{d:.3},{:.3},{zi:.2},{di:.2}",
        d / z
    );
}

fn main() {
    let milliseconds = std::env::var("ZD_BENCH_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(25)
        .max(1);
    let samples = std::env::var("ZD_BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(9)
        .clamp(5, 101)
        | 1;
    let target = Duration::from_millis(milliseconds);
    let valid = fixtures::valid_fixtures();
    let invalid = fixtures::invalid_fixtures();
    for fixture in &valid {
        assert_eq!(
            zdwire_snapshot(&fixture.wire).unwrap(),
            domain_snapshot(&fixture.wire).unwrap(),
            "{} semantic mismatch",
            fixture.name
        );
        assert_eq!(
            zdwire_raw(&fixture.wire).unwrap(),
            domain_raw(&fixture.wire).unwrap(),
            "{} raw digest",
            fixture.name
        );
        assert_eq!(
            zdwire_typed(&fixture.wire).unwrap(),
            domain_typed(&fixture.wire).unwrap(),
            "{} typed digest",
            fixture.name
        );
    }
    for fixture in &valid {
        assert_eq!(
            zdwire_typed(&fixture.wire).unwrap(),
            domain_specialized(&fixture.wire).unwrap(),
            "{} specialized digest",
            fixture.name
        );
    }
    for fixture in &invalid {
        assert!(
            zdwire_raw(&fixture.wire).is_err(),
            "{} zdwire accepted",
            fixture.name
        );
        assert!(
            domain_raw(&fixture.wire).is_err(),
            "{} domain accepted",
            fixture.name
        );
    }
    eprintln!("domain=0.12.3 default-features=false; samples={samples}; target_ms={milliseconds}; all semantic checks passed");
    println!(
        "mode,case,bytes,zdwire_ns,domain_ns,domain_over_zdwire,zdwire_iqr_pct,domain_iqr_pct"
    );
    for fixture in &valid {
        measure(
            "raw",
            fixture.name,
            fixture.wire.len(),
            || zdwire_raw(black_box(&fixture.wire)).unwrap(),
            || domain_raw(black_box(&fixture.wire)).unwrap(),
            target,
            samples,
        );
        measure(
            "typed-generic",
            fixture.name,
            fixture.wire.len(),
            || zdwire_typed(black_box(&fixture.wire)).unwrap(),
            || domain_typed(black_box(&fixture.wire)).unwrap(),
            target,
            samples,
        );
    }
    for fixture in &valid {
        measure(
            "typed",
            fixture.name,
            fixture.wire.len(),
            || zdwire_typed(black_box(&fixture.wire)).unwrap(),
            || domain_specialized(black_box(&fixture.wire)).unwrap(),
            target,
            samples,
        );
    }
    for fixture in &invalid {
        measure(
            "reject",
            fixture.name,
            fixture.wire.len(),
            || zdwire_raw(black_box(&fixture.wire)).is_err() as u64,
            || domain_raw(black_box(&fixture.wire)).is_err() as u64,
            target,
            samples,
        );
    }
    let mut zoutput = vec![0; 65535];
    let mut doutput = vec![0; 65535];
    for case in encode::cases() {
        for compressed in [false, true] {
            let zlen = encode::zdwire(&case, &mut zoutput, compressed);
            let dlen = encode::domain(&case, &mut doutput, compressed);
            assert_eq!(
                &zoutput[..zlen],
                &doutput[..dlen],
                "{} compressed={compressed} output differs",
                case.name
            );
            measure(
                if compressed {
                    "encode-compressed"
                } else {
                    "encode-plain"
                },
                case.name,
                zlen,
                || {
                    let len = encode::zdwire(black_box(&case), black_box(&mut zoutput), compressed);
                    black_box(&zoutput[..len]);
                    len as u64
                },
                || {
                    let len = encode::domain(black_box(&case), black_box(&mut doutput), compressed);
                    black_box(&doutput[..len]);
                    len as u64
                },
                target,
                samples,
            );
        }
    }
}
