# MaMa Imunify scanner gateway

Standalone mTLS HTTP gateway and callback hook for submitting individual files to ImunifyAV and returning normalized scan results. This repository contains application code and tests only; runtime credentials, certificates, host-specific settings, and deployment files are intentionally excluded.

Results identify the tested engine as `imunifyav`. They must not be described as ImunifyAV+ results unless that paid product is separately licensed and tested.

## Tests

```sh
python -m unittest discover -s tests -v
```
