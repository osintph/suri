# Wordlists Attribution

Suri uses wordlists derived from [SecLists](https://github.com/danielmiessler/SecLists) by Daniel Miessler, Jason Haddix, and contributors.

SecLists is licensed under the MIT License.

## Embedded (vendored) wordlists

The following files are embedded in the Suri binary via `go:embed`. They are curated subsets of the corresponding SecLists files, filtered and annotated for web application security testing.

| File | Source file in SecLists | SecLists ref |
|------|------------------------|-------------|
| `wordlists/embedded/admin-common.txt` | `Discovery/Web-Content/common.txt` | `2024.4` |
| `wordlists/embedded/api-paths.txt` | `Discovery/Web-Content/directory-list-2.3-small.txt` + hand-curated REST paths | `2024.4` |
| `wordlists/embedded/swagger-paths.txt` | Hand-curated from common application observations | n/a |

The embedded lists are intentionally smaller than the full SecLists originals. Run `suri wordlists update` to download the full SecLists files to the local cache, which takes precedence over the embedded lists during scans.

## Pinned SecLists commit

The `wordlists update` command fetches from SecLists at the pinned reference:

```
Tag:          2024.4
Approx. date: 2024-10-01
```

The pin is defined in `internal/wordlists/wordlists.go` (`PinnedCommit` constant). Bump it and rebuild to use a newer SecLists release. Verify that the SecLists paths in `seclistsFetches` still exist in the new tag before committing the bump.

## Fetched files (cached tier)

When `suri wordlists update` runs, it downloads these SecLists files to `~/.cache/suri/wordlists/`:

| Local name | SecLists path |
|------------|--------------|
| `admin-common.txt` | `Discovery/Web-Content/common.txt` |
| `api-paths.txt` | `Discovery/Web-Content/directory-list-2.3-small.txt` |

`swagger-paths.txt` is hand-curated and is not fetched from SecLists.

## Loading precedence

Checks that use wordlists follow this tier order (highest precedence first):

1. User-supplied via `--wordlist` / `-w` flag on `suri scan`
2. Cached at `~/.cache/suri/wordlists/` (populated by `suri wordlists update`)
3. Vendored (embedded in binary)

The `wordlist_source` column on each finding records which tier was used, for example `vendored:admin-common.txt`, `cached:seclists/admin-common.txt`, or `user:/path/to/list.txt`.

## SecLists license

> MIT License
>
> Copyright (c) 2014 Daniel Miessler
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
