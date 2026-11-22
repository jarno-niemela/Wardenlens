# Wardenlens

Rust workspace developed with an agent-driven, ticket-based workflow:
Sonnet implements; Opus reviews, audits security and attacks the code before anything merges.

- Contributor/agent guide: [`CLAUDE.md`](CLAUDE.md)
- Workflow, labels and merge gate: [`docs/WORKFLOW.md`](docs/WORKFLOW.md)
- Coding guidelines: [`docs/CODING_GUIDELINES.md`](docs/CODING_GUIDELINES.md)

## Quick start
```bash
git config core.hooksPath .githooks
scripts/gate                     # full local quality gate
cargo run -p wardenlens-cli      # prints the version
```
In Claude Code: `/plan-epic <idea>` → `/work --loop`.
