# CoconutGo

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://github.com/jstuczyn/CoconutGo/blob/master/LICENSE)
[![Build Status](https://travis-ci.com/jstuczyn/CoconutGo.svg?branch=master)](https://travis-ci.com/jstuczyn/CoconutGo)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/jstuczyn/CoconutGo)
[![Coverage Status](http://codecov.io/github/jstuczyn/CoconutGo/coverage.svg?branch=master)](http://codecov.io/github/jstuczyn/CoconutGo?branch=master)

This is a Go implementation of the Coconut selective disclosure cerendtial scheme by Sonnino et al.: [https://arxiv.org/pdf/1802.07344.pdf](https://arxiv.org/pdf/1802.07344.pdf).
It supports threshold issuance on multiple public and private attributes, re-randomization and multiple unlinkable selective attribute revelations.

The implementation is based on the existing Python version: [https://github.com/asonnino/coconut](https://github.com/asonnino/coconut)

## Pre-requisites

To run the code, first of all you need to follow standard Go installation procedure as described in [https://golang.org/doc/install](https://golang.org/doc/install).

Then follow the instructions at [https://github.com/milagro-crypto/amcl/tree/master/version3/go](https://github.com/milagro-crypto/amcl/tree/master/version3/go) in order to install the Apache Milagro Cryptographic Library that is used for cryptographic primitives. Note that currently CoconutGo uses BLS381, so make sure you select it as the option during the library setup.

## Test

In order to run tests, firstly install Testify package:

```bash
go get github.com/stretchr/testify
```

Then simply run the tests with:

```bash
go test -v ./...
```

### Benchmarks

todo