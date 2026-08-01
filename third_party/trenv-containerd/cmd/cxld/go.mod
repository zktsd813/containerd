module github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld

go 1.17

require (
	github.com/containerd/containerd v0.0.0
	github.com/containernetworking/cni v1.1.1
	github.com/hanwen/go-fuse/v2 v2.5.1
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	go.etcd.io/etcd/api/v3 v3.5.7
	go.etcd.io/etcd/client/v3 v3.5.7
	golang.org/x/sys v0.2.0
	google.golang.org/grpc v1.47.0
	google.golang.org/protobuf v1.28.0
)

require (
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.7 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/net v0.0.0-20220722155237-a158d28d115b // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220502173005-c8bf987b8c21 // indirect
)

replace github.com/containerd/containerd => ../../../..
