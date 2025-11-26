FROM cgr.dev/chainguard/go:latest-dev AS builder

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-fPIC -O -D__BLST_PORTABLE__"
ENV CGO_CFLAGS_ALLOW="-O -D__BLST_PORTABLE__"
ENV CGO_LDFLAGS="-s -w -Wl,-z,stack-size=0x800000"

COPY . /src

# Build the Go binary
WORKDIR /src
RUN go build -tags urfave_cli_no_docs,ckzg -trimpath -v -o /src/build/bin/geth /src/cmd/geth

# Final image
FROM cgr.dev/chainguard/wolfi-base:latest
RUN apk add --no-cache jq libgcc wget

ENV LD_LIBRARY_PATH=/usr/lib/
EXPOSE 8545 8546 30303 30303/udp

COPY --from=builder /src/build/bin/geth /usr/bin/geth
COPY ./build/version.json /etc/version.json

ENV GETH_MINER_RECOMMIT=2s
COPY ./build/entrypoint-l2.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

STOPSIGNAL SIGINT
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
