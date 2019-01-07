# Release Checklist

## Prerequisites

* [Go](https://golang.org>) 1.10 or later. Note: older versions might still work but have not been tested.
* [protoc](https://github.com/protocolbuffers/protobuf) version3.

## Release Processs

* ensure local copy of the repository is on master and up-to-date:

```bash
cd $GOPATH/src/0xacab.org/jstuczyn/CoconutGo
git checkout master
git pull origin master
```

* run all tests and ensure they pass:

```bash
cd $GOPATH/src/0xacab.org/jstuczyn/CoconutGo
go test -v ./...
```

* ensure protobuf-generated files did not unexpectedly change:

```bash
cd $GOPATH/src/0xacab.org/jstuczyn/CoconutGo
go generate
git diff $GOPATH/src/0xacab.org/jstuczyn/CoconutGo/crypto/elgamal/types.pb.go
git diff $GOPATH/src/0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme/types.pb.go
git diff $GOPATH/src/0xacab.org/jstuczyn/CoconutGo/server/commands/types.pb.go
git diff $GOPATH/src/0xacab.org/jstuczyn/CoconutGo/server/comm/grpc/services/services.pb.go
```

* create appropriate version tag according to [Semantic Versioning](https://semver.org/) to reflect extent of changes made:

```bash
cd $GOPATH/src/0xacab.org/jstuczyn/CoconutGo
git tag -s vX.Y.Z
git push origin vX.Y.Z
```

* update changelog.md with appropriate information reflecting changes in the new version.
