//! Adversarial tests of `open_regular_nofollow` / `is_symlink_refusal` (#64).

use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use wardenlens_fsutil::{FsError, is_symlink_refusal, open_regular_nofollow};

#[test]
fn symlink_in_last_component_is_refused_but_trailing_slash_never_reads_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f");
    std::fs::write(&file, b"x").unwrap();
    let lfile = dir.path().join("lf");
    symlink(&file, &lfile).unwrap();
    let ldir = dir.path().join("ld");
    symlink(dir.path(), &ldir).unwrap();

    assert!(is_symlink_refusal(
        &open_regular_nofollow(&lfile).unwrap_err()
    ));
    let mut s = lfile.into_os_string();
    s.push("/");
    assert!(open_regular_nofollow(&PathBuf::from(s)).is_err());
    let mut d = ldir.into_os_string();
    d.push("/");
    assert!(matches!(
        open_regular_nofollow(&PathBuf::from(d)),
        Err(FsError::NotRegular)
    ));
}

#[test]
fn a_symlink_loop_in_a_parent_is_not_a_symlink_refusal_of_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    symlink(&b, &a).unwrap();
    symlink(&a, &b).unwrap();
    let e = open_regular_nofollow(&a.join("f")).unwrap_err();
    assert!(
        !is_symlink_refusal(&e),
        "ELOOP from a parent loop is classified as the last component being a symlink: {e}"
    );
}

#[test]
fn the_descriptor_reads_the_whole_file_and_size_matches() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big");
    let bytes = vec![b'a'; 200_000];
    std::fs::write(&p, &bytes).unwrap();
    let (mut f, st) = open_regular_nofollow(&p).unwrap();
    let mut got = Vec::new();
    f.read_to_end(&mut got).unwrap();
    assert_eq!(got.len(), bytes.len());
    assert_eq!(st.size, 200_000);
}

#[test]
fn empty_path_and_unix_socket_are_errors() {
    assert!(open_regular_nofollow(std::path::Path::new("")).is_err());
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    assert!(open_regular_nofollow(&sock).is_err());
}
