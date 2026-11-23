# Wardenlens

**A modern, agentic video monitoring system (NVR) that adapts itself to the cameras and GPU you actually own.**

Wardenlens is being built to record, index and analyse video from IP cameras. Where other NVRs reduce every camera
to its lowest common denominator, Wardenlens aims to use each camera's own capabilities: native event channels,
on-camera person detection and vendor-specific stream settings. Detection will run on whatever GPU or accelerator
the host has.

The goal for new hardware support is an agentic development process: AI agents characterise a device, implement
and verify the support, and open a pull request with the evidence. Each merged PR then becomes ready-made
configuration that everyone with the same hardware can use. The project itself is already written this way; the
pipeline for adding new hardware is planned (epics #33 and #34).

> **Status:** early development, not usable yet. The Phase 0 spikes are done (camera spike S1, GPU spike S2, live
> event captures), and a few follow-up spikes are still open. Phase 1 (record everything) has its design decisions
> merged (ADRs 0004-0006); implementation has not started. The binary only prints its version. See
> [Roadmap](#roadmap).

---

## Why

This project started from a practical problem: **no available NVR handled the advanced features of more than one
camera brand properly.**

A typical home or small-site install mixes vendors, for example a couple of Reolinks, a Dahua OEM bullet camera,
a TP-Link Tapo and a no-name ONVIF camera. Existing NVRs handle this mix in one of two ways:

- **Generic ONVIF/RTSP only.** Every camera works, but on-camera AI events, vendor event channels, smart encoding
  and tuning are lost, and motion has to be re-detected on the server.
- **One vendor done well,** and the others treated as dumb RTSP sources.

Each brand speaks its own dialect. Reolink pushes events over its proprietary Baichuan protocol. Dahua uses a CGI
long-poll. Tapo serves ONVIF PullPoint events on a different port from its device service. Some cameras have flaky
ONVIF implementations. Supporting all of this well, by hand, for every model is more work than any one maintainer
can keep up with.

Wardenlens takes the other route: **it is designed to tune itself to the hardware it finds.** What follows is the
target design; see [Roadmap](#roadmap) for what exists today.

- **Cameras:**
  - It discovers each camera and characterises it read-only: streams, GOP, ONVIF capabilities, vendor APIs and
    event formats.
  - It picks the best native integration available for each one.
  - With the owner's approval, it can configure the camera for maximum capability: it shows a diff, applies the
    change on approval, and can revert it.
- **GPU:** it benchmarks the GPU or accelerator and chooses decode, motion and inference settings that fit it. For
  example, a GTX 970 gets NVDEC H.264 on sub-streams, NVRTC-compiled motion kernels and ONNX Runtime YOLO at a
  measured frame budget.
- **Unknown hardware:** when Wardenlens meets hardware it doesn't know, the agentic pipeline produces a capability
  report and a ticket, then implements the support with tests built from recorded, redacted fixtures. The result
  goes upstream as a PR with **verifiable provenance**, so the next user with that camera or GPU gets it
  automatically (epics #33 and #34).

## Features (planned and in progress)

| Area | What Wardenlens does |
|---|---|
| Recording | 24/7 passthrough recording of main streams (no re-encode) into fragmented-MP4 segments that survive a crash, cut on keyframes, indexed in SQLite |
| Storage tiers | Fast SSD "hot" tier plus a large HDD archive. A crash-safe move protocol, a per-volume free-space floor (default 25 %), and archive outages handled without losing the index |
| Native events | Reolink Baichuan push, Dahua `eventManager` long-poll, ONVIF PullPoint (Tapo and others), with the camera's own AI detections where the camera reports them |
| GPU intelligence | Motion and false-alarm filtering plus object detection on the local GPU, adapted to the measured hardware |
| Web UI | A LAN web UI with a live grid sized to the viewport, motion recaps, full-screen live or last-event playback, and Recent and Archive views |
| API | An API-first design: an OpenAPI-described HTTP API with bearer tokens, LAN-only binding by default |
| Camera optimizer | Reads camera settings, proposes improvements with a diff, applies them on approval and can revert them |
| Secrets | Credentials and site data (addresses, MACs, serials, names) kept in an encrypted vault rather than config files, with an exact-match leak scan on commits (ADR 0006; not built yet) |
| Deployment | Docker with GPU access; production (pinned release) and staging environments |

### Hardware characterised so far

These camera models have been probed read-only and documented in [ADR 0002](docs/adr/0002-camera-integration.md).
A machine-readable camera catalogue (`cameras/`) is planned (#32):

| Camera | Integration found |
|---|---|
| Reolink RLC-520A | RTSP H.264; Baichuan login and motion push (port 9000); HTTP/HTTPS API off on the tested unit; person detection enabled in its config, but no AI event seen over Baichuan yet (#78) |
| Dahua OEM IPC-HFW4431R-Z | RTSP; CGI `eventManager` long-poll with motion start/stop; ONVIF present (not yet exercised in depth) |
| TP-Link Tapo C110 | RTSP; ONVIF PullPoint with `Motion` and `People` topics (live captures in `spikes/s1-cameras/results/events/`) |
| RTT-8700 (generic) | RTSP; ONVIF present but unreliable |

GPU: NVIDIA GTX 970 (Maxwell, sm_52), benchmarked in [ADR 0003](docs/adr/0003-gpu-stack.md). It uses NVDEC H.264
only, cudarc with NVRTC kernels, ONNX Runtime 1.20.2 with the CUDA EP, CUDA 12.9 and driver branch 580.

## Architecture

Wardenlens is a Rust workspace built as a *functional core with adapter crates*. The domain logic is pure and fully
unit-testable; all I/O lives in adapters that implement the core's traits (ports). The binary is the composition root.
The crate map below is the design from ADRs 0004-0006. Today only `core` and `cli` exist; each crate is created by the
ticket that first needs it.

```
                               wardenlens (cli): config, wiring, tokio runtime, logging, commands
                                 │  (composition root: depends on every crate below)
   ┌──────┬───────┬────────┬─────┴────┬────────┬─────────┬─────────┬─────────┐
  api   index  storage   ingest    recorder   onvif   agentdvr    vault     fsutil
 (axum, (SQLite (tiers,   (RTSP)  (segments) (SOAP,   (import)  (encrypted (openat2 root
 OpenAPI) index) mover)              │        WS-Disc)           store,     handles, safe
   │       │      │         │        ▼         │         │       leak scan)  file opens)
   │       │      │         │       mp4        │         │          │
   │       │      │         │     (fMP4        │         │          ▼
   │       │      │         │      writer)     │         │       secrets
   │       │      │         │        │         │         │     (key file,
   │       │      │         │        │         │         │      seal/open)
   └───────┴──────┴─────────┴────────┴─────────┴─────────┴──────────┴──▶ core
                 pure domain types, policy, config parsing, ports (traits); no I/O
```

Extra edges not drawn: `index`, `vault`, `storage` and `recorder` also use `fsutil`. `api` depends on `core` only and
reaches the stores and segment files through core ports (for example `SegmentFiles`), never through another adapter.

**Planned data flow (Phase 1; the native events and the web UI come in Phase 2):**

```
camera ──RTSP──▶ ingest ──timestamped frames──▶ recorder ──fMP4 segments──▶ hot tier (SSD) ──mover──▶ archive (HDD)
                                                    │
                                                    └── segment rows ──▶ index (SQLite) ◀── api ◀── clients
```

Key design decisions are recorded as Architecture Decision Records:

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-agentic-ticket-workflow.md) | Ticket-driven agentic workflow and the SHA-bound merge gate |
| [0002](docs/adr/0002-camera-integration.md) | Per-vendor camera integration: streams, event channels, quirks, live event captures |
| [0003](docs/adr/0003-gpu-stack.md) | GPU stack for Maxwell: NVDEC, cudarc and NVRTC, ONNX Runtime, CUDA 12.9 |
| [0004](docs/adr/0004-service-architecture.md) | Service architecture: tokio, axum, utoipa, crate map, API token auth, LAN-only transport, connection limits |
| [0005](docs/adr/0005-recording-storage.md) | Recording format: in-house fMP4 writer, segment rules, SQLite index, crash-safe tier moves and reconciliation, `fsutil` |
| [0006](docs/adr/0006-sensitive-data-store.md) | Encrypted sensitive-data vault (XChaCha20-Poly1305) and the exact-match leak scan |

Design principles (from [`docs/CODING_GUIDELINES.md`](docs/CODING_GUIDELINES.md) and the ADRs):

- **Code safety:** no `unsafe` (`forbid` across the workspace), no panics in non-test code, and typed errors.
- **Untrusted input:** everything from a camera, the network or the disk is treated as untrusted, and is bounded and
  validated.
- **File paths:** derived only from validated ids and timestamps (SEC-4); ADR 0005 adds opening them beneath a root
  handle with `openat2`.
- **Tests and dependencies:** tests first, with property tests for parsers. Dependencies are justified and checked by
  `cargo-deny`.

## How this project is built: agentic development

Wardenlens is written almost entirely by AI agents under a strict, auditable process. The human owner sets
direction, answers design questions and approves anything that touches physical hardware. Agents do everything
else: planning, implementation, review, security audit, adversarial testing and merging. The process is designed
so that **no change reaches `main` without independent verification bound to the exact commit**. That rule is
enforced by the project's own tooling and agent guard; GitHub itself does not enforce the verification statuses.

### Roles

| Role | Model | Responsibility |
|---|---|---|
| Controller | Claude Opus (main session) | Picks tickets, dispatches agents, keeps labels truthful, merges. Never writes production code |
| Planner | Claude Opus | Breaks an epic into small, ordered, testable tasks; proposes ADR spikes |
| Implementer | **Claude Sonnet** | Writes tests and code for one ticket on its own branch and worktree, and runs the gate |
| Reviewer | **Claude Opus** | Code quality, design and test quality against the coding guidelines (cites rule IDs) |
| Security auditor | **Claude Opus** | Threat model of the diff: trust boundaries, untrusted input, DoS, secrets, supply chain |
| Adversary | **Claude Opus** | Assumes the change is broken and tries to prove it with failing tests and hostile inputs |

*Sonnet implements, Opus verifies.* Each verifier runs in a fresh context that never saw the implementer's
reasoning, so it judges the diff, the ticket and the code, not the story. The adversary works in its own detached
worktree at the exact commit under test.

### Lifecycle of a change

```
GitHub issue (type:task, Epic: #N)
   │  scripts/ticket claim
   ▼
Implementer (Sonnet) ── tests first ── code ── scripts/gate ── commit
   │  controller re-runs the gate itself, pushes, opens a PR
   ▼
┌──────────── in parallel, fresh contexts, same commit SHA ────────────┐
│  Reviewer (Opus)     Security auditor (Opus)     Adversary (Opus)    │
└──────────────────────────────────┬───────────────────────────────────┘
        any blocker/major?  ── yes ──▶ consolidated findings ──▶ Implementer fixes ──▶ all three re-verify
                 │ no                     (max 5 rounds; minors become follow-up tickets)
                 ▼
 scripts/verify mark → SHA-bound commit statuses verify/quality, verify/security, verify/adversarial
                 ▼
 gh pr merge --squash --match-head-commit <verified SHA>   (only if all three statuses + CI are green)
```

- **Tickets are the source of truth.** No work happens without a GitHub issue. Every open issue carries exactly one
  `status:*` label, maintained by `scripts/ticket` and CI automation. `scripts/ticket-audit` finds neglected or
  mislabelled tickets.
- **Merges are bound to the commit.** The verification gate is a set of commit statuses bound to the exact SHA
  that was verified. A later push invalidates them. `scripts/verify check` refuses a head that is not fully
  verified, and the agent guard requires the merge to name that SHA with `--match-head-commit`. Adversary tests worth
  keeping are added afterwards as test-only commits, and `scripts/verify carry` refuses anything else.
- **Owner overrides are recorded.** When the cap is reached, the owner decides: rethink, fold in a fix and re-verify,
  or merge and track the gap in a ticket. The decision is written on the PR.
- **Findings are graded.** Only blocker and major findings fail a round. Minor findings are filed as follow-up
  tickets, so reviews converge instead of looping.
- **The round cap is a design signal.** If a change still fails after 5 rounds, it stops and goes to the human.
  Hitting the cap means "rethink the design", not "try harder". A heuristic secret filter that never converged in
  five rounds is being replaced by the exact-match vault scan of ADR 0006 (designed, not built yet).
- **Design before code.** Significant decisions (crates, formats, protocols, security) are made in ADR spikes that
  go through the same three-verifier process as code. Scratch prototypes and probes back their claims: a
  throwaway fMP4 writer, `cargo deny` checks, live captures of camera events.

### Guardrails

- **`scripts/gate`** runs before every push: `rustfmt`, `clippy -D warnings`, tests, tooling tests, `shellcheck`,
  docs and `cargo-deny`. Lints are never weakened and tests are never deleted to get green.
- **Hooks:**
  - A Claude Code hook blocks force-pushes, pushes to `main`, `--no-verify`, `--admin` and merges without
    `--match-head-commit`.
  - The `.githooks/pre-push` hook is the authoritative block on rewriting `main`.
  - Enforcement files (hooks, settings, workflows) are protected by permission rules, the best-effort Bash guard
    and the pre-push hook. A change to them is treated as a privilege change for a human to make.
- **Sensitive data.** The repository is public. Camera credentials, LAN addresses, MACs, serials and names are kept
  outside the repo by policy. The controller screens every agent prompt with `scripts/agents check`, and the
  verifiers re-check committed evidence, which is redacted. An exact-match leak scan in the gate and git hooks is
  planned (ADR 0006).
- **Hardware is read-only.** Agents probe cameras read-only. Any write, even a temporary one, needs the owner's
  explicit approval. It is recorded with its before and after state, and reverted.
- **Agents survive usage limits.** In-flight subagents are tracked in a ledger (`scripts/agents`), so work
  interrupted by usage limits resumes where it stopped instead of being redone.

The full process is documented in [`docs/WORKFLOW.md`](docs/WORKFLOW.md), the agent definitions are in
[`.claude/agents/`](.claude/agents/), and the skills (`/work`, `/plan-epic`, `/verify`, `/new-ticket`,
`/ticket-audit`) are in [`.claude/skills/`](.claude/skills/).

### Sharing hardware support (planned: epics #33 and #34)

None of this exists yet. The plan is that each camera or GPU Wardenlens learns becomes a reviewed PR:

- **A catalogue entry** (`cameras/<vendor>/<model>.toml`), with a support level and evidence.
- **Driver or profile code,** with tests that replay redacted fixtures, so CI never needs the device.
- **A provenance record** showing that the ticket, implementer, three verifiers and SHA-bound statuses were all
  present.

Anyone with the same model would then get that configuration when they update. Reports about unknown hardware from
Wardenlens installs would become tickets, and the same pipeline would turn them into support.

## Roadmap

| Phase | Epic | Goal |
|---|---|---|
| 0 | #15 | Foundations: host setup, camera spike (S1), GPU spike (S2), live event captures. **Spikes done; follow-ups open** (#28, #78) |
| 1 | #16 | Record everything: ingest, fMP4 segments, SQLite index, hot and archive tiers, API, vault, Docker. 48 h soak gate. **Design merged (ADRs 0004-0006); implementation next** |
| 2 | #17 | Native camera events and the web UI. Cut-over from the previous NVR |
| 3 | #18 | GPU intelligence: motion, false-alarm filtering, object detection |
| 4 | #19 | Polish and the camera optimizer |
| - | #33, #34 | Agentic camera and GPU support with provenance (planned) |
| - | #25 | In-app assistant for chat-driven configuration and tuning (planned) |

## Quick start (development)

Requirements: Linux and the Rust toolchain pinned in `rust-toolchain.toml`. `cargo-deny` and `shellcheck` are
recommended; `scripts/gate` skips them locally when they are missing, and CI runs them. Docker and the NVIDIA
container toolkit are needed later for GPU work.

```bash
git config core.hooksPath .githooks   # required; the gate checks it
scripts/gate                          # full local quality gate
cargo run -p wardenlens-cli           # prints the version (the service is not wired up yet)
```

With Claude Code:

```text
/plan-epic <idea or #epic>     # plan an epic into tickets
/work --loop                   # implement and verify ready tickets one by one
scripts/ticket next            # what is next
```

## Repository map

| Path | Contents |
|---|---|
| `crates/wardenlens-core` | Pure domain logic (no I/O) |
| `crates/wardenlens-cli` | The `wardenlens` binary |
| `docs/adr/` | Architecture Decision Records |
| `docs/WORKFLOW.md`, `docs/CODING_GUIDELINES.md` | Process and coding rules |
| `spikes/` | Hardware spikes: camera probes (S1) and GPU benchmarks (S2), with redacted results |
| `scripts/` | `gate`, `ticket`, `ticket-audit`, `verify`, `agents` |
| `.claude/` | Agent definitions, skills and guard hooks for Claude Code |
| `CLAUDE.md` | Instructions for agents working in this repository |

## License

Not yet licensed. All rights reserved until a license is chosen.
