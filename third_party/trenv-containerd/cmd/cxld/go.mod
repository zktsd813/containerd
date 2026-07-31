module github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld

go 1.17

require (
	github.com/containerd/containerd v0.0.0
	github.com/containernetworking/cni v1.1.1
	github.com/hanwen/go-fuse/v2 v2.5.1
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	golang.org/x/sys v0.2.0
	google.golang.org/protobuf v1.28.0
)

replace github.com/containerd/containerd => ../../../..
