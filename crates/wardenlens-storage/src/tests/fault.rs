//! A fault-injecting [`Fs`]: fails the n-th call of one system-call kind. In `dead` mode every
//! call after the fault fails too, which leaves the files exactly as a power cut at that point
//! would (the cleanup of the mover cannot run either).

use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex, PoisonError};

use rustix::io::Errno;
use wardenlens_core::storage::Tier;
use wardenlens_fsutil::{DirEntry, FsError, QuarantineOutcome};

use crate::{Fs, Opened, PartFile, RealFs, SourceFile};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    Open(Tier),
    Mkdir(Tier),
    SyncDir(Tier),
    Unlink(Tier),
    CreatePart,
    Rename,
    Quarantine(Tier),
    List(Tier),
    Read,
    SyncSource,
    Write,
    SyncPart,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Fault {
    pub(crate) op: Op,
    /// 1-based occurrence of `op` that fails.
    pub(crate) nth: u32,
    /// Every later occurrence fails too.
    pub(crate) sticky: bool,
    /// After the fault, every call of any kind fails (a crash).
    pub(crate) dead: bool,
    pub(crate) errno: Errno,
    /// A faulting `Read` reports end of file instead of an error (a file that shrank).
    pub(crate) eof: bool,
}

impl Fault {
    pub(crate) fn once(op: Op, nth: u32) -> Self {
        Self {
            op,
            nth,
            sticky: false,
            dead: false,
            errno: Errno::IO,
            eof: false,
        }
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub(crate) fault: Option<Fault>,
    pub(crate) counts: HashMap<Op, u32>,
    pub(crate) fired: bool,
    pub(crate) log: Vec<Op>,
    /// `list_dir` reports every entry as kind `Other` (a filesystem that gives `DT_UNKNOWN`).
    pub(crate) unknown_kinds: bool,
}

pub(crate) type Shared = Arc<Mutex<State>>;

pub(crate) fn hit(shared: &Shared, op: Op) -> Option<Fault> {
    let mut s = shared.lock().unwrap_or_else(PoisonError::into_inner);
    s.log.push(op);
    let n = {
        let c = s.counts.entry(op).or_insert(0);
        *c += 1;
        *c
    };
    let f = s.fault?;
    if s.fired && f.dead {
        return Some(f);
    }
    if f.op == op && (n == f.nth || (f.sticky && n > f.nth)) {
        s.fired = true;
        return Some(f);
    }
    None
}

pub(crate) fn count(shared: &Shared, op: Op) -> u32 {
    *shared.lock().unwrap().counts.get(&op).unwrap_or(&0)
}

pub(crate) struct FaultFs {
    inner: RealFs,
    pub(crate) state: Shared,
}

impl FaultFs {
    pub(crate) fn new(inner: RealFs, state: Shared) -> Self {
        Self { inner, state }
    }

    fn check(&self, op: Op) -> Result<(), FsError> {
        match hit(&self.state, op) {
            Some(f) => Err(FsError::Io {
                op: "injected",
                source: f.errno,
            }),
            None => Ok(()),
        }
    }
}

struct FaultSource {
    inner: Box<dyn SourceFile>,
    state: Shared,
}

impl Read for FaultSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(f) = hit(&self.state, Op::Read) {
            if f.eof {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(f.errno.raw_os_error()));
        }
        self.inner.read(buf)
    }
}

impl SourceFile for FaultSource {
    fn sync(&mut self) -> io::Result<()> {
        if let Some(f) = hit(&self.state, Op::SyncSource) {
            return Err(io::Error::from_raw_os_error(f.errno.raw_os_error()));
        }
        self.inner.sync()
    }
}

struct FaultPart {
    inner: Box<dyn PartFile>,
    state: Shared,
}

impl PartFile for FaultPart {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if let Some(f) = hit(&self.state, Op::Write) {
            return Err(io::Error::from_raw_os_error(f.errno.raw_os_error()));
        }
        self.inner.write_all(buf)
    }
    fn sync(&mut self) -> io::Result<()> {
        if let Some(f) = hit(&self.state, Op::SyncPart) {
            return Err(io::Error::from_raw_os_error(f.errno.raw_os_error()));
        }
        self.inner.sync()
    }
}

impl Fs for FaultFs {
    fn open_read(&self, tier: Tier, comps: &[&str]) -> Result<Opened, FsError> {
        self.check(Op::Open(tier))?;
        let o = self.inner.open_read(tier, comps)?;
        Ok(Opened {
            file: Box::new(FaultSource {
                inner: o.file,
                state: Arc::clone(&self.state),
            }),
            len: o.len,
        })
    }
    fn mkdir(&self, tier: Tier, parent: &[&str], name: &str) -> Result<(), FsError> {
        self.check(Op::Mkdir(tier))?;
        self.inner.mkdir(tier, parent, name)
    }
    fn sync_dir(&self, tier: Tier, dir: &[&str]) -> Result<(), FsError> {
        self.check(Op::SyncDir(tier))?;
        self.inner.sync_dir(tier, dir)
    }
    fn unlink(&self, tier: Tier, dir: &[&str], name: &str) -> Result<(), FsError> {
        self.check(Op::Unlink(tier))?;
        self.inner.unlink(tier, dir, name)
    }
    fn create_part(
        &self,
        tier: Tier,
        dir: &[&str],
        name: &str,
    ) -> Result<Box<dyn PartFile>, FsError> {
        self.check(Op::CreatePart)?;
        let f = self.inner.create_part(tier, dir, name)?;
        Ok(Box::new(FaultPart {
            inner: f,
            state: Arc::clone(&self.state),
        }))
    }
    fn rename_noreplace(
        &self,
        tier: Tier,
        dir: &[&str],
        from: &str,
        to: &str,
    ) -> Result<(), FsError> {
        self.check(Op::Rename)?;
        self.inner.rename_noreplace(tier, dir, from, to)
    }
    fn quarantine(&self, tier: Tier, comps: &[&str]) -> Result<QuarantineOutcome, FsError> {
        self.check(Op::Quarantine(tier))?;
        self.inner.quarantine(tier, comps)
    }
    fn list_dir(&self, tier: Tier, dir: &[&str], max: usize) -> Result<Vec<DirEntry>, FsError> {
        self.check(Op::List(tier))?;
        let mut v = self.inner.list_dir(tier, dir, max)?;
        if self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unknown_kinds
        {
            for e in &mut v {
                e.kind = wardenlens_fsutil::FileKind::Other;
            }
        }
        Ok(v)
    }
}
