//! Tests of the git sources against temporary repositories and synthetic vault values.
//!
//! Each fixture holds one distinct value in one place, so a finding names the source that
//! produced it. The "dropping a source" tests (TEST-8) show that each fixture depends on its
//! source: with the source switched off, the value is no longer found.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_vault::{Matcher, ScanEntry};

use super::*;

const V_BLOB: &str = "zq-blobval-1001";
const V_PATH: &str = "zq-pathval-1002";
const V_BIN: &str = "zq-binval-1003";
const V_MSG: &str = "zq-msgval-1004";
const V_AUTH: &str = "zq-authval-1005";
const V_COMM: &str = "zq-commval-1006";
const V_MERGE: &str = "zq-mergeval-1007";
const V_TAGMSG: &str = "zq-tagmsgval-1008";
const V_TAGGER: &str = "zq-taggerval-1009";
const V_TAGHDR: &str = "zq-taghdrval-1010";
const V_REF: &str = "zq-refval-1011";
const V_RENAME: &str = "zq-renameval-1012";
const V_TWO: &str = "zq-twopathval-1013";

const ALL_VALUES: [(&str, &str); 11] = [
    ("e:blob", V_BLOB),
    ("e:path", V_PATH),
    ("e:bin", V_BIN),
    ("e:msg", V_MSG),
    ("e:auth", V_AUTH),
    ("e:comm", V_COMM),
    ("e:merge", V_MERGE),
    ("e:tagmsg", V_TAGMSG),
    ("e:tagger", V_TAGGER),
    ("e:taghdr", V_TAGHDR),
    ("e:ref", V_REF),
];

fn matcher(values: &[(&str, &str)]) -> Matcher {
    matcher_of_kind(values, EntryKind::Other)
}

fn matcher_of_kind(values: &[(&str, &str)], kind: EntryKind) -> Matcher {
    let entries: Vec<ScanEntry> = values
        .iter()
        .map(|(id, v)| ScanEntry {
            id: EntryId::new(id).unwrap(),
            kind,
            value: SecretString::from((*v).to_owned()),
            unscannable: false,
        })
        .collect();
    let m = Matcher::new(&entries).unwrap();
    assert_eq!(m.unscannable().len(), 0);
    m
}

struct Repo {
    dir: TempDir,
}

impl Repo {
    fn new() -> Self {
        let r = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        r.git(&[], &["init", "-q", "-b", "main"]);
        r
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn git(&self, env: &[(&str, &str)], args: &[&str]) -> String {
        let mut c = Command::new("git");
        c.current_dir(self.path())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "A U Thor")
            .env("GIT_AUTHOR_EMAIL", "author@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_NAME", "C O Mitter")
            .env("GIT_COMMITTER_EMAIL", "committer@example.invalid")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .args(args);
        for (k, v) in env {
            c.env(k, v);
        }
        let out = c.output().unwrap();
        assert!(out.status.success(), "git {args:?} failed");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.path().join(OsStr::from_bytes(name.as_bytes())), bytes).unwrap();
    }

    fn commit(&self, env: &[(&str, &str)], message: &str) -> String {
        self.git(&[], &["add", "-A"]);
        self.git(env, &["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&[], &["rev-parse", "HEAD"])
    }

    fn sha(&self, rev: &str) -> Sha {
        Sha::parse(self.git(&[], &["rev-parse", rev]).as_bytes()).unwrap()
    }

    fn range(&self, from: Option<&str>, to: &str, sources: Sources, m: &Matcher) -> Collected {
        self.range_with(from, to, None, &[], sources, m)
    }

    fn range_with(
        &self,
        from: Option<&str>,
        to: &str,
        remote: Option<&str>,
        refs: &[String],
        sources: Sources,
        m: &Matcher,
    ) -> Collected {
        let from = from.map(|f| self.sha(f));
        collect_range(
            m,
            &Git::at(self.path()),
            (from.as_ref(), &self.sha(to), remote),
            refs,
            sources,
        )
        .unwrap()
    }

    fn staged(&self, sources: Sources, m: &Matcher) -> Collected {
        collect_staged(m, &Git::at(self.path()), sources).unwrap()
    }

    /// A merge of `side` into `main` whose `mergetag` header embeds a tag with `V_MERGE` in its
    /// message. (`git merge` adds that header only for some tag merges, so the commit is written
    /// by hand.)
    fn merge_with_mergetag(&self, side: &str) {
        let (main, side_sha) = (
            self.git(&[], &["rev-parse", "main"]),
            self.git(&[], &["rev-parse", side]),
        );
        let tree = self.git(&[], &["rev-parse", &format!("{side}^{{tree}}")]);
        let who = "A U Thor <author@example.invalid> 1767225600 +0000";
        let raw = format!(
            "tree {tree}\nparent {main}\nparent {side_sha}\nauthor {who}\ncommitter {who}\n\
mergetag object {side_sha}\n type commit\n tag side-tag\n tagger {who}\n \n {V_MERGE}\n\nmerge side\n"
        );
        let sha = self.git_in(
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            raw.as_bytes(),
        );
        self.git(&[], &["update-ref", "refs/heads/main", &sha]);
    }

    fn git_in(&self, args: &[&str], stdin: &[u8]) -> String {
        use std::io::Write as _;
        use std::process::Stdio;
        let mut child = Command::new("git")
            .current_dir(self.path())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// The repository with one value in each place a push publishes. Returns the tag that
    /// names the whole history.
    fn rich(&self) -> String {
        self.write("a.txt", format!("alpha\n{V_BLOB}\n").as_bytes());
        self.commit(&[], "initial");
        self.write(&format!("notes-{V_PATH}.txt"), b"clean text\n");
        self.commit(&[], "add notes");
        let mut bin = vec![0u8, 1, 2, 0xff, 0];
        bin.extend_from_slice(V_BIN.as_bytes());
        bin.extend_from_slice(&[0, 3, 4]);
        self.write("bin.dat", &bin);
        self.commit(&[], "binary");
        self.write("m.txt", b"m\n");
        self.commit(&[], &format!("subject {V_MSG}"));
        self.write("p.txt", b"p\n");
        self.commit(&[("GIT_AUTHOR_NAME", V_AUTH)], "by a named author");
        self.write("q.txt", b"q\n");
        self.commit(&[("GIT_COMMITTER_NAME", V_COMM)], "by a named committer");
        self.git(&[], &["checkout", "-q", "-b", "side"]);
        self.write("side.txt", b"s\n");
        self.commit(&[], "side");
        self.git(&[], &["checkout", "-q", "main"]);
        self.merge_with_mergetag("side");
        let tag = format!("rel-{V_TAGHDR}");
        self.git(
            &[("GIT_COMMITTER_NAME", V_TAGGER)],
            &["tag", "-a", "-m", V_TAGMSG, &tag],
        );
        tag
    }
}

fn ids(c: &Collected) -> BTreeSet<String> {
    c.findings.iter().map(|f| f.id.to_string()).collect()
}

fn expect(ids_found: &BTreeSet<String>, want: &[&str]) {
    let want: BTreeSet<String> = want.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(*ids_found, want);
}

// ---- a range: every source, one distinct value each -----------------------------------------

#[test]
fn a_push_is_scanned_in_every_place_it_publishes() {
    let r = Repo::new();
    let tag = r.rich();
    let m = matcher(&ALL_VALUES);
    let refs = [format!("refs/heads/feature-{V_REF}")];
    let c = r.range_with(None, &tag, None, &refs, Sources::ALL, &m);
    expect(
        &ids(&c),
        &[
            "e:blob", "e:path", "e:bin", "e:msg", "e:auth", "e:comm", "e:merge", "e:tagmsg",
            "e:tagger", "e:taghdr", "e:ref",
        ],
    );
    assert_eq!(c.problems.len(), 0);
    let at = |id: &str| {
        c.findings
            .iter()
            .find(|f| f.id.as_str() == id)
            .map(|f| f.at.clone())
            .unwrap()
    };
    // Content: the text blob names its line, the binary blob does not.
    assert!(matches!(at("e:blob"), Where::Blob { line: Some(2), .. }));
    assert!(matches!(at("e:bin"), Where::Blob { line: None, .. }));
    assert!(matches!(at("e:path"), Where::BlobPath { .. }));
    assert!(matches!(at("e:msg"), Where::Commit(_, Part::Message)));
    assert!(matches!(at("e:auth"), Where::Commit(_, Part::Author)));
    assert!(matches!(at("e:comm"), Where::Commit(_, Part::Committer)));
    // The embedded tag of a merge is a header of the commit, `mergetag`.
    assert!(matches!(at("e:merge"), Where::Commit(_, Part::Header)));
    assert!(matches!(at("e:tagmsg"), Where::Tag(_, Part::Message)));
    assert!(matches!(at("e:tagger"), Where::Tag(_, Part::Tagger)));
    assert!(matches!(at("e:taghdr"), Where::Tag(_, Part::Header)));
    assert_eq!(at("e:ref"), Where::Ref(0));
}

#[test]
fn dropping_a_source_loses_exactly_its_values() {
    // TEST-8: each fixture above fails if its source is not scanned.
    let r = Repo::new();
    let tag = r.rich();
    let m = matcher(&ALL_VALUES);
    let refs = [format!("refs/heads/feature-{V_REF}")];
    let run = |s: Sources| ids(&r.range_with(None, &tag, None, &refs, s, &m));
    let all = run(Sources::ALL);
    let missing = |s: Sources| -> BTreeSet<String> { all.difference(&run(s)).cloned().collect() };
    let set = |v: &[&str]| -> BTreeSet<String> { v.iter().map(|s| (*s).to_owned()).collect() };
    assert_eq!(
        missing(Sources::ALL.without(Sources::BLOBS)),
        set(&["e:blob", "e:bin"])
    );
    assert_eq!(
        missing(Sources::ALL.without(Sources::PATHS)),
        set(&["e:path"])
    );
    assert_eq!(
        missing(Sources::ALL.without(Sources::COMMITS)),
        set(&["e:msg", "e:auth", "e:comm", "e:merge"])
    );
    assert_eq!(
        missing(Sources::ALL.without(Sources::TAGS)),
        set(&["e:tagmsg", "e:tagger", "e:taghdr"])
    );
    assert_eq!(
        missing(Sources::ALL.without(Sources::REFS)),
        set(&["e:ref"])
    );
}

// ---- paths of the new commits -----------------------------------------------------------------

#[test]
fn a_rename_of_unchanged_content_is_found_by_its_new_path() {
    let r = Repo::new();
    r.write("plain.txt", b"nothing to see\n");
    let base = r.commit(&[], "base");
    r.git(&[], &["mv", "plain.txt", &format!("moved-{V_RENAME}.txt")]);
    r.commit(&[], "rename");
    let m = matcher(&[("e:rename", V_RENAME)]);
    let c = r.range(Some(&base), "HEAD", Sources::ALL, &m);
    expect(&ids(&c), &["e:rename"]);
    // The blob is not new: only the path source can have found it.
    let c = r.range(
        Some(&base),
        "HEAD",
        Sources::ALL.without(Sources::PATHS),
        &m,
    );
    expect(&ids(&c), &[]);
}

#[test]
fn one_blob_at_two_paths_is_found_at_its_second_path() {
    let r = Repo::new();
    r.write("one.txt", b"same content\n");
    r.write(&format!("two-{V_TWO}.txt"), b"same content\n");
    r.commit(&[], "two paths, one blob");
    let m = matcher(&[("e:two", V_TWO)]);
    let c = r.range(None, "HEAD", Sources::ALL, &m);
    expect(&ids(&c), &["e:two"]);
    // The blob has both paths in the listing, so a report can name it by neither.
    let blob = r.sha("HEAD:one.txt");
    assert_eq!(c.paths.get(&blob).map(Vec::len), Some(2));
    let shown = c
        .findings
        .iter()
        .map(|f| render(&m, &loc(&f.at, &c.paths)).to_string())
        .collect::<Vec<_>>();
    assert!(shown.iter().all(|s| !s.contains(V_TWO)), "{shown:?}");
    assert!(
        shown.iter().all(|s| s.starts_with("<redacted-path> blob ")),
        "{shown:?}"
    );
}

#[test]
fn a_merge_is_diffed_against_each_parent() {
    let r = Repo::new();
    r.write("base.txt", b"b\n");
    let base = r.commit(&[], "base");
    r.git(&[], &["checkout", "-q", "-b", "side"]);
    r.write(&format!("side-{V_PATH}.txt"), b"s\n");
    r.commit(&[], "side");
    r.git(&[], &["checkout", "-q", "main"]);
    r.write("main.txt", b"m\n");
    r.commit(&[], "main");
    r.git(&[], &["merge", "-q", "--no-ff", "-m", "merge", "side"]);
    let m = matcher(&[("e:path", V_PATH)]);
    // Against the first parent the side file is the merge's own change; against the second it
    // is unchanged: `-m` reports it for the merge commit as well as for the side commit.
    let c = r.range(Some(&base), "HEAD", Sources::ALL, &m);
    assert!(c.findings.len() >= 2, "{:?}", c.findings);
    expect(&ids(&c), &["e:path"]);
}

// ---- already published --------------------------------------------------------------------------

#[test]
fn commits_the_destination_already_has_are_not_scanned_again() {
    let r = Repo::new();
    r.write("old.txt", format!("{V_BLOB}\n").as_bytes());
    let old = r.commit(&[], "published long ago");
    r.git(&[], &["update-ref", "refs/remotes/origin/main", &old]);
    r.write("new.txt", b"fine\n");
    r.commit(&[], "new");
    let m = matcher(&[("e:blob", V_BLOB)]);
    let scan =
        |remote: Option<&str>| ids(&r.range_with(None, "HEAD", remote, &[], Sources::ALL, &m));
    expect(&scan(Some("origin")), &[]);
    // Without the exclusion, and with another remote's name, the old blob counts as new.
    expect(&scan(None), &["e:blob"]);
    expect(&scan(Some("elsewhere")), &["e:blob"]);
    // A base commit excludes its history the same way.
    let c = r.range(Some(&old), "HEAD", Sources::ALL, &m);
    expect(&ids(&c), &[]);
}

// ---- the index ------------------------------------------------------------------------------------

#[test]
fn the_staged_blob_is_scanned_not_the_working_tree() {
    let r = Repo::new();
    r.write("a.txt", format!("x\n{V_BLOB}\n").as_bytes());
    r.git(&[], &["add", "a.txt"]);
    r.write("a.txt", b"the working tree is clean now\n");
    let m = matcher(&[("e:blob", V_BLOB)]);
    let c = r.staged(Sources::ALL, &m);
    expect(&ids(&c), &["e:blob"]);
    assert!(matches!(
        c.findings.first().map(|f| &f.at),
        Some(Where::Index { line: Some(2), .. })
    ));
    let c = r.staged(Sources::ALL.without(Sources::BLOBS), &m);
    expect(&ids(&c), &[]);
}

#[test]
fn a_staged_path_binary_blob_and_second_path_are_scanned() {
    let r = Repo::new();
    r.write(&format!("name-{V_PATH}.txt"), b"clean\n");
    let mut bin = vec![0u8, 9, 0];
    bin.extend_from_slice(V_BIN.as_bytes());
    r.write("one.bin", &bin);
    r.write("two.bin", &bin);
    r.git(&[], &["add", "-A"]);
    let m = matcher(&[("e:path", V_PATH), ("e:bin", V_BIN)]);
    let c = r.staged(Sources::ALL, &m);
    expect(&ids(&c), &["e:path", "e:bin"]);
    // The same blob at two paths is reported at both.
    assert_eq!(
        c.findings
            .iter()
            .filter(|f| f.id.as_str() == "e:bin")
            .count(),
        2
    );
    let c = r.staged(Sources::ALL.without(Sources::PATHS), &m);
    expect(&ids(&c), &["e:bin"]);
}

#[test]
fn only_what_changed_against_head_is_scanned_and_a_first_commit_works() {
    let r = Repo::new();
    let m = matcher(&[("e:blob", V_BLOB)]);
    // No commit yet and nothing staged: nothing to scan, and not an error.
    expect(&ids(&r.staged(Sources::ALL, &m)), &[]);
    r.write("old.txt", format!("{V_BLOB}\n").as_bytes());
    r.git(&[], &["add", "old.txt"]);
    expect(&ids(&r.staged(Sources::ALL, &m)), &["e:blob"]);
    r.commit(&[], "first");
    r.write("new.txt", b"clean\n");
    r.git(&[], &["add", "new.txt"]);
    expect(&ids(&r.staged(Sources::ALL, &m)), &[]);
}

#[test]
fn a_path_with_a_newline_and_a_non_utf8_byte_is_read_whole() {
    let r = Repo::new();
    let name = OsStr::from_bytes(b"line\nbreak-\xff-after.txt");
    std::fs::write(r.path().join(name), format!("{V_BLOB}\n")).unwrap();
    r.git(&[], &["add", "-A"]);
    let m = matcher(&[("e:blob", V_BLOB)]);
    let c = r.staged(Sources::ALL, &m);
    expect(&ids(&c), &["e:blob"]);
    let shown = render(&m, &loc(&c.findings[0].at, &c.paths)).to_string();
    // Escaped, never raw: no line break and no stray byte reaches the report.
    assert!(shown.contains("\\u{a}"), "{shown}");
    assert!(!shown.contains('\n'));
}

// ---- reports never print a value -------------------------------------------------------------------

#[test]
fn every_location_kind_is_redacted_when_its_text_holds_a_value() {
    // P10: one site renders every kind. Each location here is built so that its own text (the
    // object id, the position, the path) spells a vault value; the rendered text must not.
    let sha_with = |value: &str| format!("{value}{}", "0".repeat(40 - value.len()));
    let value = "deadbeefcafe";
    // A secret has no word boundary, so it can match inside an object id.
    let m = matcher_of_kind(&[("e:hex", value)], EntryKind::Secret);
    let sha = sha_with(value);
    let clean_sha = "1".repeat(40);
    let path = format!("dir/{value}/f.txt").into_bytes();
    let paths = [path.clone()];
    let locs = [
        Loc::Index {
            path: &path,
            sha: Some(&sha),
            line: Some(3),
        },
        Loc::Index {
            path: &path,
            sha: None,
            line: None,
        },
        Loc::Blob {
            paths: &paths,
            sha: &clean_sha,
            line: Some(2),
        },
        Loc::Blob {
            paths: &paths,
            sha: &sha,
            line: Some(2),
        },
        Loc::Blob {
            paths: &[],
            sha: &sha,
            line: None,
        },
        Loc::Commit {
            sha: &sha,
            part: Part::Message,
        },
        Loc::Commit {
            sha: &sha,
            part: Part::Author,
        },
        Loc::Commit {
            sha: &sha,
            part: Part::Committer,
        },
        Loc::Commit {
            sha: &sha,
            part: Part::Header,
        },
        Loc::Tag {
            sha: &sha,
            part: Part::Message,
        },
        Loc::Tag {
            sha: &sha,
            part: Part::Tagger,
        },
        Loc::Tag {
            sha: &sha,
            part: Part::Header,
        },
    ];
    for l in &locs {
        let shown = render(&m, l).to_string();
        assert!(!shown.contains(value), "{l:?} -> {shown}");
        assert_ne!(shown, "");
    }
}

#[test]
fn a_clean_location_is_printed_in_full_in_the_forms_of_the_adr() {
    let m = matcher_of_kind(&[("e:hex", "deadbeefcafe")], EntryKind::Secret);
    let clean_sha = "1".repeat(40);
    let paths = [b"dir/deadbeefcafe/f.txt".to_vec()];
    let clean = |l: Loc<'_>| render(&m, &l).to_string();
    let p = b"src/a.txt".to_vec();
    assert_eq!(
        clean(Loc::Index {
            path: &p,
            sha: Some(&clean_sha),
            line: Some(3)
        }),
        "src/a.txt:3"
    );
    assert_eq!(
        clean(Loc::Blob {
            paths: std::slice::from_ref(&p),
            sha: &clean_sha,
            line: Some(2)
        }),
        format!("src/a.txt blob {clean_sha}:2")
    );
    assert_eq!(
        clean(Loc::Commit {
            sha: &clean_sha,
            part: Part::Message
        }),
        format!("commit:{clean_sha}:message")
    );
    assert_eq!(
        clean(Loc::Tag {
            sha: &clean_sha,
            part: Part::Tagger
        }),
        format!("tag:{clean_sha}:tagger")
    );
    assert_eq!(clean(Loc::Ref(4)), "ref:4");
    // A path with a value, in a blob listing: the path is replaced, the blob stays.
    assert_eq!(
        clean(Loc::Blob {
            paths: &paths,
            sha: &clean_sha,
            line: Some(2)
        }),
        format!("<redacted-path> blob {clean_sha}:2")
    );
    // Even the position of a ref can spell a value.
    let m = matcher(&[("e:num", "1234567")]);
    assert_eq!(
        render(&m, &Loc::Ref(1_234_567)).to_string(),
        "<redacted-location>"
    );
}

#[test]
fn a_ref_name_with_a_value_is_reported_by_position_only() {
    let r = Repo::new();
    r.write("a.txt", b"x\n");
    r.commit(&[], "c");
    let m = matcher(&[("e:ref", V_REF)]);
    let refs = [
        "refs/heads/fine".to_owned(),
        format!("refs/heads/feature-{V_REF}"),
    ];
    let c = r.range_with(None, "HEAD", None, &refs, Sources::ALL, &m);
    assert_eq!(c.findings.len(), 1);
    let shown = render(&m, &loc(&c.findings[0].at, &c.paths)).to_string();
    assert_eq!(shown, "ref:1");
}

// ---- object parts ----------------------------------------------------------------------------------

#[test]
fn a_commit_or_tag_is_split_into_headers_and_message() {
    let commit = b"tree abc\nparent def\nauthor A <a@x> 1 +0000\ncommitter C <c@x> 1 +0000\n\
mergetag object 123\n type commit\n tag t\n \n body of tag\ngpgsig -----BEGIN\n  line\n\nmessage\n\nmore\n";
    let parts = split_object(commit, Kind::Commit);
    let kinds: Vec<Part> = parts.iter().map(|p| p.0).collect();
    assert_eq!(
        kinds,
        [
            Part::Header,
            Part::Header,
            Part::Author,
            Part::Committer,
            Part::Header,
            Part::Header,
            Part::Message
        ]
    );
    // The continuation lines belong to the header above, even an empty one (" ").
    let merge = String::from_utf8(parts[4].1.clone()).unwrap();
    assert!(
        merge.contains("type commit") && merge.contains("tag t"),
        "{merge}"
    );
    let tag = b"object abc\ntype commit\ntag v1\ntagger T <t@x> 1 +0000\n\nmsg\n";
    let parts = split_object(tag, Kind::Tag);
    assert_eq!(parts[3].0, Part::Tagger);
    assert_eq!(parts[4].0, Part::Message);
    // No message at all, and an author line in a tag is just a header.
    assert!(
        split_object(b"author x\n", Kind::Tag)
            .iter()
            .all(|p| p.0 == Part::Header)
    );
    assert!(
        split_object(b"", Kind::Commit)
            .iter()
            .all(|p| p.0 != Part::Message)
    );
}

#[test]
fn the_scan_does_not_write_to_the_repository() {
    // P3: a scan only reads. Every file under .git keeps its content and its modification time.
    let r = Repo::new();
    let tag = r.rich();
    r.write("staged.txt", b"s\n");
    r.git(&[], &["add", "staged.txt"]);
    let snapshot = |dir: &Path| {
        let out = Command::new("find")
            .arg(dir.join(".git"))
            .args(["-type", "f", "-printf", "%p %s %T@\\n"])
            .output()
            .unwrap();
        let mut lines: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines.sort();
        lines
    };
    let before = snapshot(r.path());
    let m = matcher(&ALL_VALUES);
    let _ = r.range(None, &tag, Sources::ALL, &m);
    let _ = r.staged(Sources::ALL, &m);
    assert_eq!(before, snapshot(r.path()));
}

#[test]
fn a_blob_over_the_limit_is_an_error_not_a_pass() {
    let r = Repo::new();
    r.write("big.txt", &vec![b'a'; MAX_OBJECT_LEN + 1]);
    r.git(&[], &["add", "-A"]);
    let m = matcher(&[("e:blob", V_BLOB)]);
    let c = r.staged(Sources::ALL, &m);
    assert_eq!(c.problems.len(), 1);
    assert!(c.findings.is_empty());
}

#[test]
fn a_missing_repository_or_revision_is_an_error() {
    let d = tempfile::tempdir().unwrap();
    let g = Git::at(d.path());
    assert!(g.staged().is_err());
    let r = Repo::new();
    let g = Git::at(r.path());
    assert!(g.resolve("no-such-revision").is_err());
    assert!(g.resolve("--help").is_err());
}
