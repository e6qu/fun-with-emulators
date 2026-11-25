# Applications (test fixture)

The application tests run programs built on application frameworks
(Electron, Visual Studio Code, Zed) on a Debian 12 root filesystem: the
packages `guests/debian/fetch/apps.txt` lists, with the programs' release
archives unpacked into `/opt`.

| Path | |
| --- | --- |
| `fetch/upstream.txt` | The release archives, fetched from their makers: each line is an archive's URL and its SHA-256 as its maker publishes it. |
| `electron/` | An Electron app of fwe's own: one window showing one page (magenta, with "fwe" in green), which the tests look at. |

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

- The Electron app in `electron/` is fwe's: MIT, as fwe is.
- Electron: MIT, with the licenses of Chromium and its other parts in the
  archive (`LICENSE`, `LICENSES.chromium.html`).
- Visual Studio Code: Microsoft's license for its builds, in the archive
  (`resources/app/LICENSE.rtf`); its source is MIT.
- Zed: GNU GPL v3 or later, its parts under the licenses its archive lists.
