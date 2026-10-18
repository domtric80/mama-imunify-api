# MaMa Imunify scanner gateway

Standalone mTLS HTTP gateway and callback hook for submitting one file to enabled local engines and returning a separate normalized result for each engine. Supported adapters are `clamav` (via `clamdscan`), `imunifyav` (on-demand scan hook), and `php-malware-scanner`. This repository contains application code and tests only; runtime credentials, certificates, host-specific settings, and deployment files are intentionally excluded.

The API returns the request identity and a `results` array with one item per enabled engine. Each item includes `engine`, `status` (`no_findings`, `findings`, or `not_evaluated`), a bounded reason code, normalized findings, engine/signature metadata when configured, profile, and elapsed time. Local paths, scanner stdout, and file names are never returned.

Engines are independently opt-in with `ENABLE_CLAMAV`, `ENABLE_IMUNIFYAV`, and `ENABLE_PHP_MALWARE_SCANNER`; all default to disabled. The gateway refuses to start when no engine is enabled. `SCAN_TMP_ROOT` and `SCAN_EVENT_ROOT` must resolve beneath tmpfs; plaintext is removed after each request. Do not enable an engine until its resource use and signatures have been verified on the node. Optional `*_ENGINE_VERSION` and `*_SIGNATURE_REVISION` environment values populate result metadata; they must be refreshed when scanner code or signatures change.

Imunify results identify the engine as `imunifyav`. They must not be described as ImunifyAV+ results unless that paid product is separately licensed and tested.

## Tests

```sh
python -m unittest discover -s tests -v
```
