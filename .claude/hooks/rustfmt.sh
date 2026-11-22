#!/usr/bin/env bash
# PostToolUse: format Rust files right after Claude edits them.
f=$(jq -r '.tool_input.file_path // ""')
[[ "$f" == *.rs && -f "$f" ]] || exit 0
# shellcheck source=/dev/null
command -v rustfmt >/dev/null || { [[ -f "$HOME/.cargo/env" ]] && . "$HOME/.cargo/env"; }
rustfmt --edition 2024 --quiet "$f" 2>/dev/null || true
exit 0
