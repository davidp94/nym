Tendermint Ethereum Watcher
===========================

An experimental library which watches the Ethereum blockchain, and notifies a Tendermint blockchain of interesting events.

TODO:

* Bust the interesting parts out of `main.go` and into library code
* Provide a simple interface for Tendermint-based applications to subscribe
* Provide a way to shoot new events into the Tendermint chain
* Config file allowing some parameters to be set:
  - number of Ethereum chain confirmations needed before events sent to Tendermint
