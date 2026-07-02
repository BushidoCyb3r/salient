# Scan Spinner Design

## Goal

Show that `defilade scan` is still running during long Elasticsearch operations.

## Behavior

- Write a rotating `| / - \\` indicator to stderr while the scan runs.
- Enable it only when stderr is an interactive terminal.
- Clear the indicator on every exit path, including errors and cancellation.
- Keep existing stdout output unchanged and avoid control characters in redirected logs.

## Implementation

Use a small standard-library helper in `cmd/defilade`. Start it immediately before
the first network request in `runScan` and stop it with `defer`. No dependency,
configuration flag, or progress-percentage API is needed.

## Verification

One focused test verifies that stopping the spinner clears its terminal line. Existing
command tests verify that normal command output remains intact.
