# Builds every Meerkat command into one image for the lab. Not for production.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY gen ./gen
COPY internal ./internal
COPY lab/mmft-testrelay ./lab/mmft-testrelay
RUN CGO_ENABLED=0 go build -o /out/ ./cmd/... ./lab/mmft-testrelay

FROM alpine:3.22
RUN apk add --no-cache iproute2 && adduser -D -H -u 10001 mmft && install -d -o mmft /var/lib/mmft/spool \
    && install -d -o mmft -m 0700 /var/lib/mmft/agent /var/lib/mmft/ca /var/lib/mmft/relay
COPY --from=build /out/ /usr/local/bin/
USER mmft
CMD ["sleep", "infinity"]
