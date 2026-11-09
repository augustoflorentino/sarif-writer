# sarif-writer

Writes SARIF 2.1.0 reports, the format GitHub code scanning, Azure DevOps and IDEs read, from C.
The document is streamed through a callback as it is written, so a report with a million results
uses the same memory as one with ten (one allocation of about 12 KiB).

- the calls follow the document: `sarw_run_begin`, `sarw_result`..., `sarw_run_end`, then
  `sarw_finish`; a call out of order returns `SARW_ERR_STATE` and writes nothing, so the output
  is always the start of a valid document
- every string is escaped; invalid UTF-8 becomes U+FFFD and sets `SARW_WARN_UTF8`
- a file path given as `sarw_location_t.path` is normalized (`\` to `/`, `.` and `..`
  resolved) and percent-encoded; with a `uriBaseId` it must stay relative, without one an
  absolute path becomes a `file://` URI. A ready URI goes in `uri` and is written as given
- output is indented with two spaces and keys come in a fixed order: the same calls give the
  same bytes, identical to Python's `json.dumps(indent=2, ensure_ascii=False)`
- C99, no dependencies

## Build and install

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build
cmake --install build --prefix /usr/local
```

From CMake, `find_package(sarif-writer REQUIRED)` and link `sarif-writer::sarif-writer`; or
`cc app.c $(pkg-config --cflags --libs sarif-writer)`.

Single file: `scripts/amalgamate.sh` writes `dist/sarif-writer/sarif-writer.h`; in one `.c` file define
`SARW_IMPLEMENTATION` before including it (and `SARW_STATIC` to keep the functions private).

## Usage

[`examples/sarif-hello.c`](examples/sarif-hello.c) writes a report with one rule and one
result. The header `include/sarif-writer/sarif-writer.h` is the API reference. In short:

```c
sarw_writer_t *w;
sarw_create(write_fn, ctx, NULL, NULL, NULL, &w); /* NULL allocator: malloc/free */
sarw_run_begin(w, &tool);                          /* tool name and rules */
sarw_result(w, &result);                           /* as many as needed */
sarw_run_end(w, NULL);                             /* or artifacts and an invocation */
sarw_finish(w);
sarw_destroy(w);
```

Every call returns `SARW_OK` or an error; `sarw_strerror` describes it. Strings are
NUL-terminated UTF-8 and are not kept after the call returns. Optional fields are `NULL`, or `0`
for numbers and counts; `rule_index` is `-1` to leave it out.

Give each result `partialFingerprints` (`sarw_result_t.fingerprints`): GitHub uses them to
recognize the same alert across uploads.

## Limits

Paths in `sarw_location_t.path` are at most 4096 bytes. Nothing else is bounded by the library;
memory does not grow with the number or size of results.

## Versioning

Semantic Versioning; see [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
