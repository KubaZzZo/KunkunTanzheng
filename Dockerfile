FROM golang:1.25.13-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/probe-server ./cmd/probe-server
RUN install -d -m 0700 -o 65532 -g 65532 /out/probe-data /out/probe-ca-private /out/probe-ca-public

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build --chown=nonroot:nonroot /out/probe-server /app/probe-server
COPY --from=build --chown=nonroot:nonroot /out/probe-data/ /var/lib/server-probe/
COPY --from=build --chown=nonroot:nonroot /out/probe-ca-private/ /var/lib/server-probe-agent-ca/
COPY --from=build --chown=nonroot:nonroot /out/probe-ca-public/ /var/lib/server-probe-agent-ca-public/
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/probe-server"]
