# Installation

The installation process of the Coconut servers takes multiple steps.

0. Ensure you have correctly installed go, set up GOPATH, etc. Also ensure you have docker and docker-compose.

1. Firstly get the copy of the repo with either `git clone git@0xacab.org:jstuczyn/CoconutGo.git` or `go get 0xacab.org/jstuczyn/CoconutGo`. The second command will only work under the assumption  the repository remains public.

2. Build the entire system by invoking `make localnet-build`.

3. If you wish to modify keys used by issuers or their configuration, modify files inside `/daemon/server/` directory. Currently those files are being coppied into docker volumes.

## Extra:

A dummy client "daemon" is provided at `0xacab.org/jstuczyn/CoconutGo/sampleclientmain/main_sample.go`. It sends dummy commands to Tendermint nodes as well as the issuers on the network.