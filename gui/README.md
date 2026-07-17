# Salient desktop console

This directory is the Wails v2 desktop module. It uses the same scan, snapshot,
map, drift, reconciliation, and declared-config packages as the CLI while
presenting them through the native operator console.

## Build

From the repository root:

```sh
make gui-deps
make gui
```

The native binary or application bundle is written under `gui/build/bin/`.
Linux webview packages and platform-specific runtime notes are documented in
[the desktop console guide](../docs/GUI.md).

## Test

```sh
cd gui
go test ./...

cd frontend
npm ci
npm test
npm run build
```

`make gui` regenerates `frontend/wailsjs`, and CI fails if those generated
bindings do not match the Go backend. Frontend code should import backend calls
through `frontend/src/bindings.js`; do not hand-edit `frontend/wailsjs`.

For live frontend development after `make gui-deps`:

```sh
cd gui
../.tools/bin/wails dev
```
