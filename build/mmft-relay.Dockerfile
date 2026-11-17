# The mmft-relay image, packaging the binary GoReleaser built. See .goreleaser.yaml.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/mmft-relay /usr/local/bin/mmft-relay
ENTRYPOINT ["/usr/local/bin/mmft-relay"]
