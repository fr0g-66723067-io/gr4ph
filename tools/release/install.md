```sh
# released lookup CLI (linux/amd64 shown; all five targets are on the release)
curl -LO https://github.com/fr0g-66723067-io/gr4ph/releases/download/v@VERSION@/gr4ph_v@VERSION@_linux_amd64
curl -LO https://github.com/fr0g-66723067-io/gr4ph/releases/download/v@VERSION@/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
chmod +x gr4ph_v@VERSION@_linux_amd64

# or use the module (Go 1.27 with GOEXPERIMENT=simd exported)
GOEXPERIMENT=simd go get github.com/fr0g-66723067-io/gr4ph@v@VERSION@
```
