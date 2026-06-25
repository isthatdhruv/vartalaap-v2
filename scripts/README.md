# Build scripts

One script per target. **Each app must be built on (or for) its own OS** — there
is no single command that produces every installer from one machine, because each
platform uses a different system webview.

| Script | Produces | Run it on | Output |
|---|---|---|---|
| `build-linux-appimage.sh` | **`.AppImage`** — portable single file, no install, runs on any modern Linux distro | any Linux **with Docker** | `packaging/out/*.AppImage` |
| `build-linux-deb.sh` | **`.deb`** for `apt` users | any Linux **with Docker** | `packaging/out/*.deb` |
| `build-macos.sh` | **`.dmg`** (universal: Intel + Apple Silicon) | **macOS** | `app/src-tauri/target/universal-apple-darwin/release/bundle/dmg/*.dmg` |
| `build-windows.sh` | **`.exe`** (NSIS installer) | **Windows** (Git Bash) | `app/src-tauri/target/release/bundle/nsis/*.exe` |

The two Linux scripts build inside an Ubuntu 22.04 container, so the result runs
on **Ubuntu 22.04+ / Debian 12+ / Fedora 36+** regardless of your own distro.

## One-shot alternative: GitHub Actions

`.github/workflows/release.yml` builds **all four** (Linux `.deb`+`.AppImage`,
Windows `.exe`, macOS Intel + Apple Silicon `.dmg`) in the cloud on every manual
run or `v*` tag — no local toolchains needed. Push the repo, then
**Actions → Release → Run workflow**.

## Hard limit

Tauri 2 requires `webkit2gtk-4.1`, which only exists on ~2022+ Linux. Ubuntu
≤ 20.04 (glibc < 2.35) cannot run this app — a framework constraint, not a
packaging one.
