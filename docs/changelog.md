# CoconutGo Changelog

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
