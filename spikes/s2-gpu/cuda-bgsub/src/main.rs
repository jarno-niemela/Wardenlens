//! S2 spike: frame-difference background subtraction on a 640x480 grey frame, compiled for sm_52 via NVRTC
//! and launched with cudarc. Spike only (uses `unsafe` for kernel launch, which the workspace forbids).
use cudarc::driver::{CudaContext, LaunchConfig, PushKernelArg};
use cudarc::nvrtc::{CompileOptions, compile_ptx_with_opts};
use std::time::Instant;

const W: usize = 640;
const H: usize = 480;
const THR: i32 = 24;

const SRC: &str = r#"
extern "C" __global__ void bgsub(const unsigned char* frame, unsigned char* bg, unsigned char* mask,
                                 unsigned int* count, int n, int thr) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    int f = frame[i];
    int b = bg[i];
    int d = f > b ? f - b : b - f;
    unsigned char m = d > thr ? 255 : 0;
    mask[i] = m;
    if (m) atomicAdd(count, 1u);
    bg[i] = (unsigned char)(b + ((f - b) >> 3));   // running-average background update
}
"#;

/// Synthetic frame `t`: static gradient plus a bright 40x40 square moving across the frame.
fn frame(t: usize) -> Vec<u8> {
    let mut v = vec![0u8; W * H];
    for y in 0..H {
        for x in 0..W {
            v[y * W + x] = ((x + y) % 128) as u8;
        }
    }
    let (ox, oy) = ((t * 7) % (W - 40), (t * 3) % (H - 40));
    for y in oy..oy + 40 {
        for x in ox..ox + 40 {
            v[y * W + x] = 250;
        }
    }
    v
}

fn cpu_ref(frame: &[u8], bg: &mut [u8], mask: &mut [u8]) -> u32 {
    let mut c = 0;
    for i in 0..frame.len() {
        let (f, b) = (i32::from(frame[i]), i32::from(bg[i]));
        let m = (f - b).abs() > THR;
        mask[i] = if m { 255 } else { 0 };
        c += u32::from(m);
        bg[i] = (b + ((f - b) >> 3)) as u8;
    }
    c
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = CudaContext::new(0)?;
    let (maj, min) = ctx.compute_capability()?;
    println!("device: {} sm_{maj}{min}", ctx.name()?);
    let ptx = compile_ptx_with_opts(
        SRC,
        CompileOptions {
            arch: Some("sm_52"),
            ..Default::default()
        },
    )?;
    let module = ctx.load_module(ptx)?;
    let f = module.load_function("bgsub")?;
    let stream = ctx.default_stream();
    let n = (W * H) as i32;
    let cfg = LaunchConfig::for_num_elems(n as u32);

    // Correctness vs CPU reference over 30 frames.
    let first = frame(0);
    let mut bg_d = stream.clone_htod(&first)?;
    let mut mask_d = stream.alloc_zeros::<u8>(W * H)?;
    let mut cnt_d = stream.alloc_zeros::<u32>(1)?;
    let (mut bg_c, mut mask_c) = (first.clone(), vec![0u8; W * H]);
    for t in 1..=30 {
        let fr = frame(t);
        let fr_d = stream.clone_htod(&fr)?;
        stream.memset_zeros(&mut cnt_d)?;
        let mut b = stream.launch_builder(&f);
        b.arg(&fr_d)
            .arg(&mut bg_d)
            .arg(&mut mask_d)
            .arg(&mut cnt_d)
            .arg(&n)
            .arg(&THR);
        unsafe { b.launch(cfg) }?;
        let gpu_count = stream.clone_dtoh(&cnt_d)?[0];
        let cpu_count = cpu_ref(&fr, &mut bg_c, &mut mask_c);
        let gpu_mask = stream.clone_dtoh(&mask_d)?;
        assert_eq!(gpu_count, cpu_count, "count mismatch at frame {t}");
        assert_eq!(gpu_mask, mask_c, "mask mismatch at frame {t}");
    }
    println!("correctness: GPU == CPU reference over 30 frames (counts and masks identical)");

    // Throughput 1: kernel only, frame resident on device.
    let iters = 20_000;
    let fr_d = stream.clone_htod(&frame(5))?;
    for _ in 0..100 {
        let mut b = stream.launch_builder(&f);
        b.arg(&fr_d)
            .arg(&mut bg_d)
            .arg(&mut mask_d)
            .arg(&mut cnt_d)
            .arg(&n)
            .arg(&THR);
        unsafe { b.launch(cfg) }?;
    }
    stream.synchronize()?;
    let t0 = Instant::now();
    for _ in 0..iters {
        let mut b = stream.launch_builder(&f);
        b.arg(&fr_d)
            .arg(&mut bg_d)
            .arg(&mut mask_d)
            .arg(&mut cnt_d)
            .arg(&n)
            .arg(&THR);
        unsafe { b.launch(cfg) }?;
    }
    stream.synchronize()?;
    let s = t0.elapsed().as_secs_f64();
    println!(
        "kernel only (device resident): {:.0} frames/s, {:.1} us/frame",
        f64::from(iters) / s,
        s / f64::from(iters) * 1e6
    );

    // Throughput 2: end to end per frame: H2D upload (pageable) + kernel + D2H of the 4-byte count.
    let host = frame(9);
    let mut up_d = stream.alloc_zeros::<u8>(W * H)?; // allocated once; each iteration only copies into it
    let iters = 5_000;
    let t0 = Instant::now();
    let mut total = 0u64;
    for _ in 0..iters {
        stream.memcpy_htod(&host, &mut up_d)?;
        stream.memset_zeros(&mut cnt_d)?;
        let mut b = stream.launch_builder(&f);
        b.arg(&up_d)
            .arg(&mut bg_d)
            .arg(&mut mask_d)
            .arg(&mut cnt_d)
            .arg(&n)
            .arg(&THR);
        unsafe { b.launch(cfg) }?;
        total += u64::from(stream.clone_dtoh(&cnt_d)?[0]);
    }
    let s = t0.elapsed().as_secs_f64();
    println!(
        "end to end (H2D copy into preallocated buffer + kernel + D2H count): {:.0} frames/s, {:.1} us/frame (checksum {total})",
        f64::from(iters) / s,
        s / f64::from(iters) * 1e6
    );
    Ok(())
}
