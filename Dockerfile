FROM golang:1.26.9-alpine AS builder
WORKDIR /app
ARG VERSION=1.1.3
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o xsscan ./cmd

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/xsscan /usr/local/bin/xsscan
ENTRYPOINT ["xsscan"]
