# Codex status line

Configure Codex's native TUI footer to mirror the useful fields from the existing Claude status line: current directory, Git branch, model with reasoning level, remaining context, five-hour usage, and weekly usage. Preserve every unrelated Codex setting. Do not copy the shell renderer because Codex does not support command-backed footer rendering; use only documented native status-line item IDs and verify the resulting TOML.
