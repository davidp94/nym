# CoconutGo Changelog

## v0.0.4

* Reimplementation of JobQueue with different queue implementation to introduce thread safety

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
