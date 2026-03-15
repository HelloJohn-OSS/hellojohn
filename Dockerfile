FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/hellojohn ./cmd/service

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/hellojohn .
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["./hellojohn"]
