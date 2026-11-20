# IOCCC entries (test fixture)

Winning entries of the International Obfuscated C Code Contest, which the
`ioccc_winners_run_as_their_authors_say` test builds as Linux arm64
programs and runs under fwe: 1984's anonymous entry, 1987's korn, and two
that print programs closing a cycle, 2000's dhyang and 2018's endoh2.
Nothing is vendored here.

## Fetched, not vendored

`fetch/winners.txt` lists each entry's file: a path under the contest's
repository at a pinned commit
(`https://raw.githubusercontent.com/ioccc-src/winner/<commit>/`, the
commit named in the manifest and in the test) and the file's SHA-256. The
test checks each checksum and caches the files under
`target/fetched-packages` (`FWE_FETCH_CACHE` overrides it).

## License

The entries are published under CC BY-SA 4.0 (Creative Commons
Attribution-ShareAlike 4.0 International), as the contest's repository
states.
