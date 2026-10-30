# Component 8.1 — loopback-only Compose apply test mode

- Added `--local-test`, which binds host `127.0.0.1:18444` to the proxy container's `18443` and does not require public-listener acknowledgement.
- Local mode uses a self-signed certificate only for an HTTPS health check pinned to the loopback interface; public mode continues to use normal certificate verification.
- Public mode and local test mode are mutually exclusive.
- Desktop wizard defaults to local test mode and requires explicit opt-out plus public-listener acknowledgement before a public apply.
- Port conflict checks in local mode focus on 18444; public mode continues to guard ports 80/443.
- Fixed source-packet build issues observed during v0.8 build: byte-slice arguments and single-quote escaping for generated Compose mounts.
- Does not implement storage-at-rest or application-level encryption.
