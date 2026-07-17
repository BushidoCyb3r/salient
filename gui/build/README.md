# Salient platform build assets

Wails uses this directory for the desktop application's platform metadata and
generated output:

- `appicon.png` — source icon for desktop bundles and Linux packages
- `darwin/` — production and development macOS property lists
- `windows/` — Windows manifest, version metadata, and installer templates
- `bin/` — generated native binaries and application bundles (ignored by Git)

Build from the repository root with `make gui`. Tagged releases build the
native macOS and Windows artifacts in CI and use `gui/nfpm.yaml` to package the
Linux binary as `.deb` and `.rpm` assets.
