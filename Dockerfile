FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -o /out/dnssec-publish-ds .
RUN mkdir -p /etc/dnssec-publish-ds/conf.d && install config/config.toml /etc/dnssec-publish-ds/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/dnssec-publish-ds /usr/sbin/dnssec-publish-ds
COPY --from=builder /etc/dnssec-publish-ds /etc/dnssec-publish-ds

VOLUME ["/var/lib/dnssec-publish-ds"]

ENTRYPOINT ["/usr/sbin/dnssec-publish-ds"]
CMD ["--config", "/etc/dnssec-publish-ds/config.toml"]
