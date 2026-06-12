# Multi-stage build for the kseal server. Build context is the repo root
# (see docker-compose.yml: context=., dockerfile=server/Dockerfile). The server
# runs its embedded SQL migrations on startup, so `docker compose up` yields a
# working system with no init scripts.

FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache dependencies first for faster incremental builds.
COPY server/go.mod server/go.sum ./
RUN go mod download

COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/kseal-server ./cmd/kseal-server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 kseal
USER kseal
COPY --from=build /out/kseal-server /usr/local/bin/kseal-server
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kseal-server"]
