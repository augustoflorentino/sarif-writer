# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 0.1.0 - 2026-11-09

First release.

- streams a SARIF 2.1.0 document through a write callback: runs with tool, driver and rules
  (descriptions, default level, tags, properties, help URI), results (rule, level, message,
  locations with line/column or byte regions, logical locations, related locations, partial
  fingerprints, properties), artifacts and an invocation with notifications
- constant memory: one allocation of about 12 KiB whatever the number of results
- calls out of order return `SARW_ERR_STATE` and write nothing; a failing write callback stops
  the writer with `SARW_ERR_WRITE`
- complete JSON escaping; invalid UTF-8 written as U+FFFD and reported by `sarw_warnings`
- artifact paths normalized and percent-encoded (RFC 3986), relative to a `uriBaseId` or as
  `file://` URIs
- output byte-identical to Python's `json.dumps(indent=2, ensure_ascii=False)` for the same
  document
