# Earthfile
VERSION 0.8

# version of go compiler to use
# remember to update both SHA versions as well
ARG --global GO_VERSION=1.23.2
ARG --global GO_SHA_AMD64=542d3c1705f1c6a1c5a80d5dc62e2e45171af291e755d591c5e6531ef63b454e
ARG --global GO_SHA_ARM64=f626cdd92fc21a88b31c1251f419c17782933a42903db87a174ce74eeecc66a9

# ------------------------- Base Images -------------------------

# Use official rust image as our rust builder
# NOTE: must use nightly-2022-12-10
rs-builder:
    FROM rust:latest
    ENV RUSTFLAGS="-C target-feature=-crt-static"
    ENV CARGO_UNSTABLE_SPARSE_REGISTRY=true
    RUN rustup default nightly-2022-12-10

INSTALL_GO_CMD:
    FUNCTION
    IF [ "$(uname -m)" = "x86_64" ]
        ENV GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
        ENV GO_URL="https://golang.org/dl/${GO_TAR}"
        ENV GO_SHA="${GO_SHA_AMD64}"
    ELSE
        ENV GO_TAR="go${GO_VERSION}.linux-arm64.tar.gz"
        ENV GO_URL="https://golang.org/dl/${GO_TAR}"
        ENV GO_SHA="${GO_SHA_ARM64}"
    END
    WORKDIR /Downloads
    RUN wget -nv "${GO_URL}"
    RUN echo "${GO_SHA} ${GO_TAR}" | sha256sum -c
    RUN tar -C /usr/ -xzf "${GO_TAR}"
    RUN rm "${GO_TAR}"
    IF [ -d "/usr/go/bin" ]
        ENV PATH=$PATH:/usr/go/bin
        ENV GOBIN=/usr/bin
    ELSE
        ENV PATH=$PATH:/usr/local/go/bin
        ENV GOBIN=/usr/local/go/bin
    END
    RUN go version
    RUN which go

GO_BUILD_DEPENDENCIES_CMD:
    FUNCTION
    WORKDIR /src
    COPY ./go.mod /src
    COPY ./go.sum /src
    RUN --secret GITHUB_TOKEN git config --global --replace-all url."https://x-access-token:${GITHUB_TOKEN}@github.com/zircuit-labs/".insteadOf "https://github.com/zircuit-labs/"
    ENV GOPRIVATE=github.com/zircuit-labs
    RUN go mod download
    RUN go mod verify
    RUN go install github.com/mfridman/tparse@latest

# Add go to the rust builder as it is required for some steps
rs-go-builder:
    FROM +rs-builder
    WORKDIR /Downloads
    DO +INSTALL_GO_CMD

# The final image on which we will deploy based on wolfi-base
# Requires jq to parse config
# Requires libgcc to use the compiled rust libs
docker-base:
    FROM cgr.dev/chainguard/wolfi-base
    RUN apk add --no-cache jq libgcc wget
    ENV LD_LIBRARY_PATH=/usr/lib/

# Add go to the deploy image to use as our go builder
go-builder:
    FROM +docker-base
    RUN apk add --no-cache git build-base
    WORKDIR /Downloads
    DO +INSTALL_GO_CMD

# ------------------------- Build Rust Libs -------------------------

# Ideally this would be a multi-stage build using cargo chef
# however `libzkp` requires the (currently) local `scroll-prover-0.7.5/prover`
# which removes any caching value from the multi-stage approach
rs-build:
    FROM +rs-go-builder
    RUN --no-cache --secret GITHUB_TOKEN git config --global --replace-all url."https://x-access-token:${GITHUB_TOKEN}@github.com/zircuit-labs/".insteadOf "https://github.com/zircuit-labs/"
    WORKDIR /app
    COPY ./rollup/circuitcapacitychecker/ .
    WORKDIR ./libzkp/
    RUN cargo build --release
    RUN find ./ | grep libzktrie.so | xargs -I{} cp {} /app/libzkp/target/release/
    SAVE ARTIFACT /app/libzkp/target/release/libzkp.so libzkp.so
    SAVE ARTIFACT /app/libzkp/target/release/libzktrie.so libzktrie.so
    RUN ls -la /app/libzkp/target/release/

# ------------------------- Build Go Binary -------------------------

# Download the go deps in an earlier stage as they seldom change
go-build-dependancies:
    FROM +go-builder
    WORKDIR /src
    DO +GO_BUILD_DEPENDENCIES_CMD

go-build-copy-source:
    FROM +go-build-dependancies
    COPY ./accounts /src/accounts
    COPY ./beacon /src/beacon
    COPY ./build /src/build
    COPY ./cmd /src/cmd
    COPY ./common /src/common
    COPY ./consensus /src/consensus
    COPY ./console /src/console
    COPY ./core /src/core
    COPY ./crypto /src/crypto
    COPY ./eth /src/eth
    COPY ./ethclient /src/ethclient
    COPY ./ethdb /src/ethdb
    COPY ./ethstats /src/ethstats
    COPY ./event /src/event
    COPY ./graphql /src/graphql
    COPY ./internal /src/internal
    COPY ./log /src/log
    COPY ./metrics /src/metrics
    COPY ./miner /src/miner
    COPY ./node /src/node
    COPY ./p2p /src/p2p
    COPY ./params /src/params
    COPY ./rlp /src/rlp
    COPY ./rollup /src/rollup
    COPY ./rpc /src/rpc
    COPY ./signer /src/signer
    COPY ./databases /src/databases
    COPY ./swarm /src/swarm
    COPY ./trie /src/trie
    COPY ./Makefile /src
    COPY ./interfaces.go /src
    DO +GO_BUILD_DEPENDENCIES_CMD

go-build-copy-source-artifact:
    FROM +go-build-copy-source
    SAVE ARTIFACT /src /src

# Build the go binary with CCC enabled
go-build-ccc:
    FROM +go-build-copy-source
    COPY +rs-build/libzkp.so /usr/lib/
    COPY +rs-build/libzktrie.so /usr/lib/
    WORKDIR /src
    ENV CGO_ENABLED=1
    RUN go run build/ci.go install -buildtags circuit_capacity_checker /src/cmd/geth
    SAVE ARTIFACT /src/build/bin/geth geth

# Build without the CCC for sanity and go unit testing
go-build-no-ccc:
    FROM +go-build-copy-source
    WORKDIR /src
    ENV CGO_ENABLED=1
    RUN go run build/ci.go install /src/cmd/geth
    SAVE ARTIFACT /src/build/bin/geth geth

# ------------------------- Build Docker Image -------------------------

docker-l2geth-ccc:
    ARG DOCKER_REGISTRY_URL
    ARG VERSION_TAG
    FROM +docker-base
    COPY +go-build-ccc/geth /usr/bin/
    COPY +rs-build/libzkp.so /usr/lib/
    COPY +rs-build/libzktrie.so /usr/lib/
    EXPOSE 8545 8546 30303 30303/udp
    ENTRYPOINT ["/usr/bin/geth"]
    SAVE IMAGE l2geth-ccc:latest
    IF [ "${DOCKER_REGISTRY_URL}" != "" ]
        SAVE IMAGE --push "${DOCKER_REGISTRY_URL}/l2geth-ccc:${VERSION_TAG}"
    END

docker-l2geth-no-ccc:
    ARG DOCKER_REGISTRY_URL
    ARG VERSION_TAG
    FROM +docker-base
    COPY +go-build-no-ccc/geth /usr/bin/
    EXPOSE 8545 8546 30303 30303/udp
    ENTRYPOINT ["/usr/bin/geth"]
    SAVE IMAGE l2geth-no-ccc:latest
    IF [ "${DOCKER_REGISTRY_URL}" != "" ]
        SAVE IMAGE --push "${DOCKER_REGISTRY_URL}/l2geth-no-ccc:${VERSION_TAG}"
    END

docker-test-integration:
    FROM earthly/dind:alpine
    DO +INSTALL_GO_CMD
    RUN apk add --no-cache git
    WORKDIR /src
    COPY +go-build-copy-source-artifact/src .
    DO +GO_BUILD_DEPENDENCIES_CMD
    SAVE IMAGE docker-test-integration:latest

# ------------------------- Testing -------------------------

go-test-unit:
    FROM +go-build-no-ccc
    WORKDIR /src
    COPY ./tests /src/tests
    RUN go test -json -timeout 600s -coverpkg="$(go list ./... | paste -d, -s -)" -covermode=atomic -coverprofile=/coverage.unit ./... | tparse -all -progress
    SAVE ARTIFACT --force /coverage.unit AS LOCAL .coverage.unit

go-test-integration:
    FROM +docker-test-integration
    WORKDIR /src
    WITH DOCKER --load go-test-integration:latest=(+docker-test-integration)
        RUN go test -json -tags=integration -timeout 600s -coverpkg="$(go list ./... | paste -d, -s -)" -covermode=atomic -coverprofile=/coverage.unit $(find . -name 'integration_*.go') | tparse -all -progress
    END

    SAVE ARTIFACT /coverage.unit AS LOCAL .coverage.unit
