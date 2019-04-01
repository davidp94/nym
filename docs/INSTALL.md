# Installation

## OUTDATED

The installation process of the Coconut servers takes multiple steps.

0. Ensure you have correctly installed go, set up GOPATH, etc.

1. Firstly get the copy of the repo with either `git clone git@0xacab.org:jstuczyn/CoconutGo.git` or `go get 0xacab.org/jstuczyn/CoconutGo`. The second command will only work under the assumption  the repository remains public.

2. [Only for a threshold system] Generate keys for all the issuing authorities by navigating to `0xacab.org/jstuczyn/CoconutGo/ttp/` and running `go install`. This will install `ttp` binary at your `$GOPATH/bin` directory. Run the tool providing the following flags:
- n - specifies number of authorities in the system,
- t - specifies the threshold level of the keys,
- attributes - specifies the maximum number of attributes the keys could sign,
- f - specifies the output directory (if left empty a keysXXXX dir will be created, where XXXX is a random number).

Sample command includes `$GOPATH/bin/ttp -attributes=5 -t=2 -n=3`

3. Navigate to `0xacab.org/jstuczyn/CoconutGo/daemon/server` and go install the server daemon. 

4. Create config files for the desired servers. The sample files (`config.toml`, `config2.toml` and `config3.toml` are provided.).

Note: that server 1 is set to be both provider and issuer. The only 'feature' of a provider server is that it accept requests to verify issued credentials. 

Note2: If the system is not using threshold credentials, you need to set `RegenerateKeys = true` in the `DEBUG` section for all isers to create fresh keys. They will be saved to `SecretKeyFile` and `VerificationKeyFile`. 

5. Start the servers by running the binary and providing the `-f` flag pointing to the location of appropriate config file. It is recommended to start the provider(s) last as they need to contact the issuers to obtain their verification keys. Currently they are set to timeout after failing to receive sufficient number of verification keys after trying for 30s. The value can be modified in the config file. Please take a look at `0xacab.org/jstuczyn/CoconutGo/server/config/config.go` for all currently available config options.

## Extra:

A dummy client "daemon" is provided at `0xacab.org/jstuczyn/CoconutGo/client/main/test_main.go`. It can be used to test functionalities of the servers by uncommenting appropriate lines in the `main` function (WIP).