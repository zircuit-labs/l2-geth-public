module github.com/zircuit-labs/l2-geth

go 1.25.3

tool (
	github.com/fjl/gencodec
	go.uber.org/mock/mockgen
	golang.org/x/tools/cmd/stringer
	mvdan.cc/gofumpt
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.6.3
	github.com/DataDog/dd-trace-go/v2 v2.3.1
	github.com/Microsoft/go-winio v0.6.2
	github.com/VictoriaMetrics/fastcache v1.13.0
	github.com/agiledragon/gomonkey/v2 v2.13.0
	github.com/alitto/pond/v2 v2.5.0
	github.com/aws/aws-sdk-go-v2 v1.39.6
	github.com/aws/aws-sdk-go-v2/config v1.31.17
	github.com/aws/aws-sdk-go-v2/credentials v1.18.21
	github.com/aws/aws-sdk-go-v2/service/route53 v1.59.1
	github.com/bits-and-blooms/bitset v1.24.2
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/cespare/cp v1.1.1
	github.com/cloudflare/cloudflare-go v0.116.0
	github.com/cockroachdb/pebble v1.1.5
	github.com/consensys/gnark-crypto v0.19.2
	github.com/crate-crypto/go-eth-kzg v1.4.0
	github.com/crate-crypto/go-ipa v0.0.0-20240724233137-53bbb0ceb27a
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/dchest/siphash v1.2.3
	github.com/deckarep/golang-set/v2 v2.8.0
	github.com/dop251/goja v0.0.0-20250630131328-58d95d85e994
	github.com/ethereum-optimism/superchain-registry/superchain v0.0.0-20250118001056-8a45400fa7a7
	github.com/ethereum/c-kzg-4844/v2 v2.1.5
	github.com/ethereum/go-verkle v0.2.2
	github.com/fatih/color v1.18.0
	github.com/ferranbt/fastssz v1.0.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/gballet/go-libpcsclite v0.0.0-20250918194357-1ec6f2e601c6
	github.com/gofrs/flock v0.12.1
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/golang/protobuf v1.5.4
	github.com/golang/snappy v1.0.0
	github.com/google/gofuzz v1.2.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/graph-gophers/graphql-go v1.8.0
	github.com/hashicorp/go-bexpr v0.1.15
	github.com/holiman/billy v0.0.0-20250707135307-f2f9b9aae7db
	github.com/holiman/bloomfilter/v2 v2.0.3
	github.com/holiman/uint256 v1.3.2
	github.com/huin/goupnp v1.3.0
	github.com/iden3/go-iden3-crypto v0.0.17
	github.com/influxdata/influxdb-client-go/v2 v2.14.0
	github.com/influxdata/influxdb1-client v0.0.0-20220302092344-a9ab5670611c
	github.com/jackpal/go-nat-pmp v1.0.2
	github.com/jedisct1/go-minisign v0.0.0-20241212093149-d2f9f49435c7
	github.com/karalabe/usb v0.0.2
	github.com/knadh/koanf v1.5.0
	github.com/kylelemons/godebug v1.1.0
	github.com/lib/pq v1.10.9
	github.com/mattn/go-colorable v0.1.14
	github.com/mattn/go-isatty v0.0.20
	github.com/naoina/toml v0.1.2-0.20170918210437-9fafd6967416
	github.com/olekukonko/tablewriter v0.0.5
	github.com/peterh/liner v1.2.2
	github.com/pion/stun/v2 v2.0.0
	github.com/prometheus/client_golang v1.23.2
	github.com/protolambda/bls12-381-util v0.1.0
	github.com/rs/cors v1.11.1
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/status-im/keycard-go v0.3.3
	github.com/stretchr/testify v1.11.1
	github.com/supranational/blst v0.3.16
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/uptrace/bun v1.2.15
	github.com/uptrace/bun/dialect/pgdialect v1.2.15
	github.com/uptrace/bun/driver/pgdriver v1.2.15
	github.com/urfave/cli/v2 v2.27.7
	github.com/zircuit-labs/zkr-go-common v1.21.2
	go.uber.org/automaxprocs v1.6.0
	go.uber.org/mock v0.6.0
	golang.org/x/crypto v0.45.0
	golang.org/x/exp v0.0.0-20250911091902-df9299821621
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.38.0
	golang.org/x/text v0.31.0
	golang.org/x/time v0.14.0
	golang.org/x/tools v0.38.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/emicklei/dot v1.6.2 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.2.1 // indirect
	github.com/pion/transport/v3 v3.0.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.5.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/theckman/httpforwarded v0.4.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	modernc.org/libc v1.66.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.38.2 // indirect
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.19.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/DataDog/datadog-agent/comp/core/tagger/origindetection v0.69.4 // indirect
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.69.4 // indirect
	github.com/DataDog/datadog-agent/pkg/proto v0.69.4 // indirect
	github.com/DataDog/datadog-agent/pkg/remoteconfig/state v0.69.4 // indirect
	github.com/DataDog/datadog-agent/pkg/trace v0.69.4 // indirect
	github.com/DataDog/datadog-agent/pkg/util/log v0.69.4 // indirect
	github.com/DataDog/datadog-agent/pkg/util/scrubber v0.69.4 // indirect
	github.com/DataDog/datadog-agent/pkg/version v0.69.4 // indirect
	github.com/DataDog/datadog-go/v5 v5.6.0 // indirect
	github.com/DataDog/go-libddwaf/v4 v4.3.2 // indirect
	github.com/DataDog/go-runtime-metrics-internal v0.0.4-0.20250721125240-fdf1ef85b633 // indirect
	github.com/DataDog/go-sqllexer v0.1.6 // indirect
	github.com/DataDog/go-tuf v1.1.0-0.5.2 // indirect
	github.com/DataDog/gostackparse v0.7.0 // indirect
	github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/attributes v0.29.0 // indirect
	github.com/DataDog/sketches-go v1.4.7 // indirect
	github.com/DataDog/zstd v1.5.6 // indirect
	github.com/Masterminds/semver/v3 v3.3.1 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.3 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.90.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.39.1 // indirect
	github.com/aws/smithy-go v1.23.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575 // indirect
	github.com/cockroachdb/errors v1.11.3 // indirect
	github.com/cockroachdb/fifo v0.0.0-20240606204812-0bbfbd93a7ce // indirect
	github.com/cockroachdb/logtags v0.0.0-20230118201751-21c54148d20b // indirect
	github.com/cockroachdb/redact v1.1.5 // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20230807174530-cc333fc44b06 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/dlclark/regexp2 v1.11.4 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ebitengine/purego v0.8.4 // indirect
	github.com/fjl/gencodec v0.1.1 // indirect
	github.com/garslo/gogen v0.0.0-20170306192744-1d203ffc1f61 // indirect
	github.com/getsentry/sentry-go v0.27.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20250607225305-033d6d78b36a // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/influxdata/line-protocol v0.0.0-20210311194329-9aa0e372d097 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20250317134145-8bc96cf8fc35 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mattn/go-sqlite3 v1.14.32 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // indirect
	github.com/mitchellh/pointerstructure v1.2.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/oapi-codegen/runtime v1.0.0 // indirect
	github.com/outcaste-io/ristretto v0.2.3 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/philhofer/fwd v1.1.3-0.20240916144458-20a13a1f6b7c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/richardartoul/molecule v1.0.1-0.20240531184615-7ca0df43c0b3 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.0 // indirect
	github.com/shirou/gopsutil/v4 v4.25.6 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tinylib/msgp v1.3.0 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/tmthrgd/go-hex v0.0.0-20190904060850-447a3041c3bc // indirect
	github.com/uptrace/bun/dialect/sqlitedialect v1.2.15
	github.com/uptrace/bun/driver/sqliteshim v1.2.15
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/collector/component v1.35.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.35.0 // indirect
	go.opentelemetry.io/collector/internal/telemetry v0.129.0 // indirect
	go.opentelemetry.io/collector/pdata v1.35.0 // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.11.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/log v0.12.2 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/grpc v1.75.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	mellium.im/sasl v0.3.2 // indirect
	mvdan.cc/gofumpt v0.8.0 // indirect
)

replace github.com/zircuit-labs/zkr-go-common => github.com/zircuit-labs/zkr-go-common-public v1.21.2
