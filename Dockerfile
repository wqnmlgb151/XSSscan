FROM golang:1.26.9-alpine3.23@sha256:6750308561953d451210ed1a8086d36c8c8bdcbf672d38d9d0d424b8a7a0216c AS builder
WORKDIR /app
ARG VERSION=1.1.4
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o xsscan ./cmd
RUN CGO_ENABLED=0 go build -trimpath -o container-fixture ./test/containerfixture

FROM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS runtime
RUN apk --no-cache add ca-certificates chromium \
    && addgroup -S xsscan && adduser -S -G xsscan -h /home/xsscan xsscan
COPY --from=builder /app/xsscan /usr/local/bin/xsscan
USER xsscan
WORKDIR /home/xsscan
ENTRYPOINT ["xsscan"]

# Test-only target; the distributed runtime image contains no fixture executable.
FROM runtime AS smoke
COPY --from=builder /app/container-fixture /usr/local/bin/container-fixture

FROM runtime AS final
