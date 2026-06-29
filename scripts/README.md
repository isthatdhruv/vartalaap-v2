# Build scripts

One script per target. **Each app must be built on (or for) its own OS** — there
is no single command that produces every installer from one machine, because each
platform uses a different system webview.

| Script | Produces | Run it on | Output |
|---|---|---|---|
| `build-linux-appimage.sh` | **`.AppImage`** — portable single file, no install (Linux 2022+) | any Linux **with Docker** | `packaging/out/*.AppImage` |
| `build-linux-deb.sh` | **`.deb`** for `apt` users (Linux 2022+) | any Linux **with Docker** | `packaging/out/*.deb` |
| `build-linux-flatpak.sh` | **`.flatpak`** — also runs on **OLD** Linux (18.04/20.04) | any Linux **with flatpak + flatpak-builder** | `packaging/out/Vartalaap.flatpak` |
| `build-macos.sh` | **`.dmg`** (universal: Intel + Apple Silicon) | **macOS** | `app/src-tauri/target/universal-apple-darwin/release/bundle/dmg/*.dmg` |
| `build-windows.sh` | **`.exe`** (NSIS installer) | **Windows** (Git Bash) | `app/src-tauri/target/release/bundle/nsis/*.exe` |

The `.deb`/`.AppImage` scripts build inside an Ubuntu 22.04 container, so the
result runs on **Ubuntu 22.04+ / Debian 12+ / Fedora 36+** regardless of your own
distro. **Do not** use a bare `tauri build` on a newer distro for distribution —
it bakes in a higher glibc floor and won't start on 22.04.

## One-shot alternative: GitHub Actions

`.github/workflows/release.yml` builds **everything** (Linux `.deb`+`.AppImage`,
the `.flatpak`, Windows `.exe`, macOS Intel + Apple Silicon `.dmg`) in the cloud
on every manual run or `v*` tag — no local toolchains needed. Push the repo, then
**Actions → Release → Run workflow**.

## Old Linux (pre-2022)

Tauri 2 requires `webkit2gtk-4.1`, which only exists on ~2022+ Linux, so the
`.deb`/`.AppImage` can't run on Ubuntu 18.04/20.04. The **`.flatpak`** is the
answer there: the GNOME runtime supplies webkit + a modern userspace inside the
sandbox, so it runs on any Linux with Flatpak installed — old or new.
