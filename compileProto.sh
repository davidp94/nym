#!/usr/bin/env bash

# elgamal

protoc -I=/home/jedrzej/go/src/github.com/jstuczyn/CoconutGo --go_out=/home/jedrzej/go/src/ /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/elgamal/proto/types.proto 


# coconut

protoc -I=/home/jedrzej/go/src/github.com/jstuczyn/CoconutGo --go_out=/home/jedrzej/go/src/ /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/coconut/scheme/proto/types.proto 

# have to move file manually as for for some reason proto expects target dir to be the same as suffix of go import path
mv /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/coconut/types.pb.go /home/jedrzej/go/src/github.com/jstuczyn/CoconutGo/crypto/coconut/scheme/types.pb.go
