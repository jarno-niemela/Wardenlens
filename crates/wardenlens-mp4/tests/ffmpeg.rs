//! Decode check against ffmpeg/ffprobe (ADR 0005 section 1). Ignored by default:
//! `cargo test -p wardenlens-mp4 -- --ignored`. Skips (passes) when ffmpeg or ffprobe is missing.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::manual_range_patterns,
    reason = "test code: helpers outside #[test] fns on synthetic data; panics are failures"
)]

use std::path::Path;
use std::process::Command;

use wardenlens_mp4::{Fragment, H264Params, Sample, annexb_to_avcc, init_segment};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/testsrc.h264");
const FRAME_TICKS: u32 = 3600; // 25 fps at 90 kHz

fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("-version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// NAL units (with header, no start code) of an Annex-B stream.
fn nal_units(data: &[u8]) -> Vec<&[u8]> {
    let starts: Vec<usize> = data
        .windows(3)
        .enumerate()
        .filter(|(_, w)| *w == [0, 0, 1])
        .map(|(i, _)| i + 3)
        .collect();
    let mut out = Vec::new();
    for (k, &s) in starts.iter().enumerate() {
        let mut end = starts.get(k + 1).map_or(data.len(), |n| n - 3);
        while end > s && data[end - 1] == 0 {
            end -= 1;
        }
        out.push(&data[s..end]);
    }
    out
}

/// Group NAL units into access units: a slice with `first_mb_in_slice == 0`, or an SEI, starts
/// a new unit once the current one holds a slice. Enough for single-slice, no-B-frame streams.
fn access_units(nals: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut aus: Vec<Vec<u8>> = Vec::new();
    let mut has_slice = false;
    for nal in nals {
        let ty = nal[0] & 0x1f;
        let is_slice = matches!(ty, 1 | 5);
        let starts_au = matches!(ty, 6 | 7 | 8 | 9) || (is_slice && nal[1] & 0x80 != 0);
        if starts_au && has_slice {
            has_slice = false;
            aus.push(Vec::new());
        }
        if aus.is_empty() {
            aus.push(Vec::new());
        }
        has_slice |= is_slice;
        let au = aus.last_mut().unwrap();
        au.extend_from_slice(&[0, 0, 0, 1]);
        au.extend_from_slice(nal);
    }
    aus
}

fn framemd5(path: &Path) -> Vec<(String, String)> {
    let out = Command::new("ffmpeg")
        .args(["-v", "error", "-xerror", "-i"])
        .arg(path)
        .args(["-f", "framemd5", "-"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ffmpeg failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let f: Vec<_> = l.split(',').map(str::trim).collect();
            (f[f.len() - 2].to_owned(), f[f.len() - 1].to_owned()) // size, md5
        })
        .collect()
}

#[test]
#[ignore = "needs ffmpeg and ffprobe; run with --ignored"]
fn muxed_file_decodes_identically_to_the_source_stream() {
    if !tool_available("ffmpeg") || !tool_available("ffprobe") {
        eprintln!("ffmpeg/ffprobe not found: skipping");
        return;
    }
    let source = std::fs::read(FIXTURE).unwrap();
    let nals = nal_units(&source);
    let sps = nals.iter().find(|n| n[0] & 0x1f == 7).unwrap();
    let pps = nals.iter().find(|n| n[0] & 0x1f == 8).unwrap();
    let params = H264Params::new(sps, pps).unwrap();
    assert_eq!((params.width(), params.height()), (320, 180));

    let samples: Vec<(Vec<u8>, bool)> = access_units(&nals)
        .iter()
        .map(|au| {
            let key = nal_units(au).iter().any(|n| n[0] & 0x1f == 5);
            (annexb_to_avcc(au).unwrap(), key)
        })
        .collect();
    assert_eq!(samples.len(), 50);

    let init = init_segment(&params).unwrap();
    let mut file = init.bytes().to_vec();
    let (mut seq, mut start) = (1u32, 0usize);
    while start < samples.len() {
        let end = samples
            .iter()
            .enumerate()
            .skip(start + 1)
            .find(|(_, s)| s.1)
            .map_or(samples.len(), |(i, _)| i);
        let group: Vec<Sample<'_>> = samples[start..end]
            .iter()
            .map(|(d, k)| Sample {
                data: d,
                duration: FRAME_TICKS,
                is_sync: *k,
            })
            .collect();
        let base = u64::try_from(start).unwrap() * u64::from(FRAME_TICKS);
        Fragment::write(seq, base, &group, &mut file).unwrap();
        seq += 1;
        start = end;
    }
    let ticks = 50 * u64::from(FRAME_TICKS);
    let patch = init.duration_patch(ticks).unwrap();
    let (m, e) = (
        usize::try_from(patch.mvhd_offset).unwrap(),
        usize::try_from(patch.mehd_offset).unwrap(),
    );
    file[m..m + 4].copy_from_slice(&patch.mvhd_value);
    file[e..e + 8].copy_from_slice(&patch.mehd_value);

    let dir = tempfile::tempdir().unwrap();
    let mp4 = dir.path().join("out.mp4");
    std::fs::write(&mp4, &file).unwrap();

    let probe = Command::new("ffprobe")
        .args(["-v", "error", "-count_frames", "-show_entries"])
        .arg("stream=codec_name,profile,width,height,time_base,nb_read_frames:format=duration")
        .args(["-of", "default=nw=1"])
        .arg(&mp4)
        .output()
        .unwrap();
    let text = String::from_utf8(probe.stdout).unwrap();
    assert!(
        probe.status.success(),
        "ffprobe failed: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    for want in [
        "codec_name=h264",
        "profile=High",
        "width=320",
        "height=180",
        "time_base=1/90000",
        "nb_read_frames=50",
        "duration=2.000000",
    ] {
        assert!(
            text.lines().any(|l| l == want),
            "missing {want} in:\n{text}"
        );
    }

    assert_eq!(
        framemd5(&mp4),
        framemd5(Path::new(FIXTURE)),
        "decoded frames differ from the source"
    );
}
