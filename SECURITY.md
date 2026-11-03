# Security policy

Meerkat MFT is in early development, and its only releases so far are release candidates. It has had no external security audit. Do not use it for real data.

## Supported versions

Release candidates are not supported, so fixes go to the `main` branch and the next release. During 0.x, security issues will be fixed in the latest release only.

## Verifying a release

Releases are built by the [release workflow](.github/workflows/release.yml) and signed keylessly with [Sigstore Cosign](https://docs.sigstore.dev/). No long-lived signing key exists. Each signature is tied to the workflow run that made it and is recorded in the public Rekor transparency log.

To check downloaded archives or SBOMs, verify the signed checksum file, then check your files against it. The checksum check runs only if the signature is valid:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/meerkat-mft/mmft/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt &&
sha256sum --check --ignore-missing checksums.txt
```

On macOS, use `shasum -a 256` in place of `sha256sum`.

To check a container image:

```bash
cosign verify ghcr.io/meerkat-mft/mmft-agent:0.1.0 \
  --certificate-identity-regexp '^https://github\.com/meerkat-mft/mmft/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub's [private vulnerability reporting](https://github.com/meerkat-mft/mmft/security/advisories/new) on this repository.

Include the affected component and version, the steps to reproduce the issue, and its likely impact.

This is a spare-time project with one maintainer, so response times are not guaranteed.
