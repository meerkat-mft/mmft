# Builds every Meerkat command into one image for the lab. Not for production.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/ ./cmd/...

FROM alpine:3.22
RUN apk add --no-cache iproute2 && adduser -D -H -u 10001 mmft && install -d -o mmft /var/lib/mmft/spool
COPY --from=build /out/ /usr/local/bin/
USER mmft
CMD ["sleep", "infinity"]
