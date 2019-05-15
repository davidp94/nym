# CoconutGo Changelog

## v0.6.2

* Dedicated configuration file for the Ethereum watcher

## v0.6.1

* "Daemon" for Ethereum watcher
* Semi-split the watcher files

## v0.6.0

* Copied the Ethereum watcher codebase to the repository
* A very initial take on Ethereum client - ability to send Nym tokens to Holding Account
* Fixed remaining old tests

## v0.5.1

* Fixed monitor/processor deadlock when there are no blocks to be processed.

## v0.5.0

* Combined tendermint node and nym abci into a single binary to significantly simplify deployment and testing
* Minor bug fixes

## v0.4.0

* All entities in the system working - full ability to issue and spend credentials.
* Fixed provider-side handling of Spend Credential
* Reintroduced blockchain keys for providers
* Fixed infinite catchup look for issuers

## v0.3.2

* Client retrying to look up credentials with specified backoff interval
* Client correctly parsing look up credential responses from the issuers
* Minor refactoring and bug fixes

## v0.3.1

* Fixed issuers not storing issued credentials

## v0.3.0

* Issuers monitoring the blockchain state
* Issuers keeping persistent state with credentials for given txs
* Issuers resyncing with the blockchain upon startup or periodically after not receiving any data during a specified interval

## v0.2.2

* Docker-compose for the entire environment
* Issuers monitoring state of the Tendermint blockchain
* Bunch of Work in Progress files related to Issuers having internal state of signed requests

## v0.2.1

* Updated transfer to the holding account to return hash of the block including the tx
* IAs verifying that transfer to holding actually happened
* Finished logic for Provider to accept 'spend credential' requests

## v0.2.0

* Tumbler-related Coconut logic for sequential and concurrent computation
* Tendermint ABCI used to keep track of clients' tokens and preventing double spending of credentials
* IAs having extra set of keys used to authorise requests on the blockchain
* Provider accepting 'spend credential' request; Interaction with the blockchain is not implemented
* Ability of a client to request transfer of some of its tokens to "Holding Account"
* Work on clients' ability to spend credentials
* Bug fixes and refactor work
* Additional tests and updates to docstrings

## v0.1.5

* More shared code between client and server
* Fixed a bug where provider server would fail to aggregate received verification keys of IAs if it received more than threshold of them (even if they all were valid)

## v0.1.4

* Made ElGamal Public and Private key fields private and only accessible via method receivers

## v0.1.3

* Refactored repository structure
* Renamed BlindSignMats and BlindShowMats to Lambda and Theta respectively
* Refactored server/CryptoWorker and simplified main processing loop
* Fixed crash on GetVerificationKey[grpc] if any server was down

## v0.1.2

* Updated milagro library to the current version as of 10.01.2019

## v0.1.1

* Reimplemented commandsQueue using the created template

## v0.1.0

* Created template to generate infinite channel behaviour for any type

## v0.0.4

* Reimplemented JobQueue with different queue implementation to introduce thread safety

## v0.0.3

* Refactored server/comm/utils/utils.go
* Introduced ServerMetadata struct used in ServerRequests/Responses + associated changes
* Renamed crypto/coconut/concurrency/coconutworker/coconut_worker.go Worker to CoconutWorker + associated changes
* Renamed client/cryptoworker/cryptoworker.go Worker to CryptoWorker + associated changes
* Refactored /home/jedrzej/go/src/0xacab.org/jstuczyn/CoconutGo/server/cryptoworker/cryptoworker.go + associated changes

## v0.0.2

* Fixes jstuczyn/CoconutGo#4

## v0.0.1 - Initial Release

* Coconut Signature Scheme
* Initial Coconut Issuing Authority Server
* Initial Coconut Provider Server
* Initial Coconut Client interacting with the above
* TTP for generating keys for the IAs
