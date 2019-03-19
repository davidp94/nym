#!/usr/bin/env bash

# elgamal
protoc --go_out=../../.. ./crypto/elgamal/proto/types.proto 

# coconut
# protoc insists on assigning package name being the same as the directory it is put in.
# Currently I do not know how to override it so sed is used as workaround.
protoc --go_out=../../.. ./crypto/coconut/scheme/proto/types.proto 
sed -i -e 's/package scheme/package coconut/g' ./crypto/coconut/scheme/types.pb.go

# tumbler-related
protoc --go_out=../../.. ./crypto/coconut/scheme/proto/tumblertypes.proto 
sed -i -e 's/package scheme/package coconut/g' ./crypto/coconut/scheme/tumblertypes.pb.go

# commands
protoc --go_out=../../.. ./common/comm/commands/proto/types.proto

# grpc
protoc ./common/grpc/services/proto/services.proto --go_out=plugins=grpc:../../..

# tendermint tx messages
protoc --go_out=../../.. ./tendermint/nymabci/transaction/proto/types.proto
