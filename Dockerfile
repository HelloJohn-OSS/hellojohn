# Dockerfile (raíz — alias para el build E2E)
# El Dockerfile completo de producción está en deployments/Dockerfile.
# Este alias expone el build en la raíz del contexto para docker-compose.
FROM golang:1.24-bookworm AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /out/hellojohn ./cmd/service

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/hellojohn .
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["./hellojohn"]
