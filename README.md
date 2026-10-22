# MaMa Imunify scanner gateway

Standalone mTLS HTTP gateway and callback hook for submitting one file to enabled local engines and returning a separate normalized result for each engine. Supported adapters are `clamav` (via `clamdscan`), `imunifyav` (on-demand scan hook), and `php-malware-scanner`. This repository contains application code and tests only; runtime credentials, certificates, host-specific settings, and deployment files are intentionally excluded.

The `POST /v1/scan` request must include `X-MaMa-Engines`, an ordered comma-separated list of engine IDs requested for that file (for example, `php-malware-scanner,clamav`). The list is protected by the mTLS connection. Missing, empty, malformed, duplicate, unknown, or disabled engine IDs are rejected with HTTP 400 before the body is staged or any scanner runs. The gateway runs only the requested engines and returns results only for those engines, in request order; it never defaults to all enabled engines.

The API returns the request identity and a `results` array with one item per requested engine. Each item includes `engine`, `status` (`no_findings`, `findings`, or `not_evaluated`), a bounded reason code, normalized findings, engine/signature metadata when configured, profile, and elapsed time. Local paths, scanner stdout, and file names are never returned.

Zero-byte files are valid scan inputs when `Content-Length` is `0` and the supplied SHA-256 is the hash of the empty payload. They are staged briefly on tmpfs and passed to each requested scanner like any other file; the temporary copy is removed after processing.

Engines are independently opt-in with `ENABLE_CLAMAV`, `ENABLE_IMUNIFYAV`, and `ENABLE_PHP_MALWARE_SCANNER`; all default to disabled. The gateway refuses to start when no engine is enabled. `SCAN_TMP_ROOT` and `SCAN_EVENT_ROOT` must resolve beneath tmpfs; plaintext is removed after each request. Do not enable an engine until its resource use and signatures have been verified on the node. Optional `*_ENGINE_VERSION` and `*_SIGNATURE_REVISION` environment values populate result metadata; they must be refreshed when scanner code or signatures change.

Scanner execution is bounded by `MAX_CONCURRENT_SCANS` (default `2`). Excess scan requests receive HTTP `429` with `Retry-After: 15` before their body is read or staged. The listening socket backlog is explicitly bounded by `REQUEST_QUEUE_SIZE` (default `64`, allowed range `5`-`256`); it does not increase scanner concurrency.

The `deploy/` directory contains a systemd unit template and a non-secret environment example. Host certificates and `/etc/mama-imunify/gateway.env` are deployment-specific and must never be committed. The unit binds only to loopback by default and restricts writable paths to the tmpfs scan root.

Imunify results identify the engine as `imunifyav`. They must not be described as ImunifyAV+ results unless that paid product is separately licensed and tested.

## Tests

```sh
python -m unittest discover -s tests -v
```
