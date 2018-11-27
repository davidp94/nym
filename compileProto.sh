#!/usr/bin/env bash

# elgamal

protoc -I=/home/jedrzej/go/src/github.com/jstuczyn/CoconutGo --go_out=/home/jedrzej/go/src/ /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/elgamal/proto/types.proto 


# coconut

protoc -I=/home/jedrzej/go/src/github.com/jstuczyn/CoconutGo --go_out=/home/jedrzej/go/src/ /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/coconut/scheme/proto/types.proto 

# have to move file manually as for for some reason proto expects target dir to be the same as suffix of go import path
# mv /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/coconut/types.pb.go /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/coconut/scheme/types.pb.go

sed -i -e 's/package scheme/package coconut/g' /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/coconut/scheme/types.pb.go

# commands

protoc -I=/home/jedrzej/go/src/github.com/jstuczyn/CoconutGo --go_out=/home/jedrzej/go/src/ /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/server/commands/proto/types.proto

# grpc

protoc -I=/home/jedrzej/go/src/github.com/jstuczyn/CoconutGo /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/server/comm/grpc/proto/services.proto --go_out=plugins=grpc:/home/jedrzej/go/src
