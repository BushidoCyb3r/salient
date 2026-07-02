# Report Browser Index Design

## Goal

Add `defilade view` to open a local browser index of saved reports and maps.

## Behavior

- Read HTML artifacts from `<data-dir>/reports` and `<data-dir>/maps`.
- Build `<data-dir>/index.html`, grouping artifacts by timestamp and sorting newest first.
- Display the existing Defilade logo and links to each report and interactive map.
- Keep the index self-contained, offline, and mode `0600`.
- Open the index with the operating system's default browser.
- On Linux, try `$BROWSER`, `gio open`, `xdg-open`, then `sensible-browser`.
- On macOS, use `open`; on Windows, use `rundll32` with `FileProtocolHandler`.
- If no launcher exists, retain the generated index and print its path in the error.

## Scope

The command is a static file index, not an HTTP server. It does not modify reports,
maps, snapshots, or scan behavior.

## Verification

Focused tests cover artifact discovery and ordering, protected index creation, and
browser-command selection without launching a real browser.
