# Applications (test fixture)

The application tests run programs built on application frameworks:
Electron, Visual Studio Code and Zed on a Debian 13 root filesystem (the
packages `guests/debian/fetch/apps.txt` lists, with the programs' release
archives unpacked into `/opt`), and apps of fwe's own made with Tauri and
Wails, built under fwe on an Alpine 3.24 root (the packages
`guests/alpine/fetch/apps.txt` lists: WebKitGTK 4.1, and Rust, Go and
clang to build them).

| Path | |
| --- | --- |
| `fetch/upstream.txt` | The release archives, fetched from their makers: each line is an archive's URL and its SHA-256 as its maker publishes it. |
| `electron/` | An Electron app of fwe's own: one window showing one page (magenta, with "fwe" in green), which the tests look at. |
| `tauri/` | A Tauri 2 app of fwe's own showing the same page, `Cargo.lock` pinning the crates it is built from (fetched by Cargo under fwe as it builds). |
| `wails/` | A Wails 2 app of fwe's own showing the same page, `go.sum` pinning the modules it is built from (fetched by Go under fwe as it builds). |

The Tauri and Wails apps are built by the tests that run them, once for
each version of their sources and of the Alpine manifest, and kept in
`target/built-apps` (CI caches it).

## Fetched, not vendored

The tests download each archive once, check its checksum and cache it
under `target/fetched-packages` (`FWE_FETCH_CACHE` overrides it; CI caches
it). Nothing fetched is redistributed in this repository.

| Archive | Program | Size |
| --- | --- | --- |
| `electron-v45.3.0-linux-arm64.zip` | Electron 45.3.0, from <https://github.com/electron/electron/releases> | 125 MB |
| `code-stable-arm64-1794014945.tar.gz` | Visual Studio Code 1.145.3, from <https://code.visualstudio.com/> | 350 MB |
| `zed-linux-aarch64.tar.gz` | Zed 1.27.0, from <https://github.com/zed-industries/zed/releases> | 86 MB |

## License

- The apps in `electron/`, `tauri/` and `wails/` are fwe's: MIT, as fwe
  is. The crates and modules they are built from are under their own
  licenses (Tauri, Wails and most of theirs: MIT or Apache-2.0), fetched
  as they are built and not redistributed here.
- Electron: MIT, with the licenses of Chromium and its other parts in the
  archive (`LICENSE`, `LICENSES.chromium.html`).
- Visual Studio Code: Microsoft's license for its builds, in the archive
  (`resources/app/LICENSE.rtf`); its source is MIT.
- Zed: GNU GPL v3 or later, its parts under the licenses its archive lists.
