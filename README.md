# CoconutGo

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://github.com/jstuczyn/CoconutGo/blob/master/LICENSE)
[![Build Status](https://travis-ci.com/jstuczyn/CoconutGo.svg?branch=master)](https://travis-ci.com/jstuczyn/CoconutGo)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/jstuczyn/CoconutGo)
[![Coverage Status](http://codecov.io/github/jstuczyn/CoconutGo/coverage.svg?branch=master)](http://codecov.io/github/jstuczyn/CoconutGo?branch=master)

This is a Go implementation of the Coconut selective disclosure cerendtial scheme by Sonnino et al.: [https://arxiv.org/pdf/1802.07344.pdf](https://arxiv.org/pdf/1802.07344.pdf).
It supports threshold issuance on multiple public and privMate attributes, re-randomization and multiple unlinkable selective attribute revelations.

The implementation is based on the existing Python version: [https://github.com/asonnino/coconut](https://github.com/asonnino/coconut)

## Pre-requisites

To run the code, you only need to follow the standard Go installation procedure as described in [https://golang.org/doc/install](https://golang.org/doc/install).

All of the requiered dependencies are attached in the vendor directory.

## Test

In order to run tests, simply use the following:

```bash
go test -v ./...
```

### Benchmarks

The benchmarks were performed on 64bit Ubuntu 18.04.1 LTS VM with 2 cores of 3.6GHz Ryzen 1600 assigned. Each individual benchmark was run single-threaded for 1 minute with `-benchtime=60s` flag.

#### BN254

| Operation                        | Times run | Time per op     | Memory per op | Allocs per op     |
|----------------------------------|-----------:|-----------------:|---------------:|-------------------:|
| G1Mul                            | 30000  | 2.41 ms/op   | 0.62 kB/op  | 12416 allocs/op   |
| G2Mul                            | 20000  | 5.87 ms/op   | 1.71 kB/op  | 35368 allocs/op   |
| Pairing                          | 3000   | 24.08 ms/op  | 7.44 kB/op  | 170229 allocs/op  |
| ElGamalEncryption                | 10000  | 7.34 ms/op   | 1.88 kB/op  | 37828 allocs/op   |
| ElGamalDecryption                | 30000  | 2.48 ms/op   | 0.62 kB/op  | 12518 allocs/op   |
|                                  |        |              |             |                   |
| Setup/q=1                        | 100000 | 0.97 ms/op   | 0.08 kB/op  | 1522 allocs/op    |
| Setup/q=3                        | 50000  | 1.44 ms/op   | 0.23 kB/op  | 4204 allocs/op    |
| Setup/q=5                        | 50000  | 2.31 ms/op   | 0.47 kB/op  | 8647 allocs/op    |
| Setup/q=10                       | 20000  | 4.00 ms/op   | 0.91 kB/op  | 16541 allocs/op   |
| Setup/q=20                       | 10000  | 6.59 ms/op   | 1.80 kB/op  | 32650 allocs/op   |
|                                  |        |              |             |                   |
| Keygen/q=1                       | 10000  | 9.53 ms/op   | 3.47 kB/op  | 71764 allocs/op   |
| Keygen/q=3                       | 5000   | 18.83 ms/op  | 6.94 kB/op  | 143543 allocs/op  |
| Keygen/q=5                       | 3000   | 28.53 ms/op  | 10.41 kB/op | 215265 allocs/op  |
| Keygen/q=10                      | 2000   | 50.35 ms/op  | 19.08 kB/op | 394701 allocs/op  |
|                                  |        |              |             |                   |
| TTPKeygen/q=1/t=3/n=5            | 2000   | 51.52 ms/op  | 17.29 kB/op | 357551 allocs/op  |
| TTPKeygen/q=3/t=3/n=5            | 1000   | 94.33 ms/op  | 34.57 kB/op | 715064 allocs/op  |
| TTPKeygen/q=5/t=3/n=5            | 1000   | 141.13 ms/op | 51.86 kB/op | 1072637 allocs/op |
| TTPKeygen/q=10/t=3/n=5           | 300    | 277.17 ms/op | 95.07 kB/op | 1966284 allocs/op |
|                                  |        |              |             |                   |
| TTPKeygen/q=3/t=1/n=5            | 1000   | 105.70 ms/op | 34.30 kB/op | 709764 allocs/op  |
| TTPKeygen/q=3/t=3/n=5            | 1000   | 94.33 ms/op  | 34.57 kB/op | 715064 allocs/op  |
| TTPKeygen/q=3/t=5/n=5            | 1000   | 100.13 ms/op | 34.87 kB/op | 720879 allocs/op  |
|                                  |        |              |             |                   |
| TTPKeygen/q=3/t=1/n=1            | 5000   | 21.91 ms/op  | 6.94 kB/op  | 143605 allocs/op  |
| TTPKeygen/q=3/t=1/n=3            | 2000   | 60.60 ms/op  | 20.62 kB/op | 426695 allocs/op  |
| TTPKeygen/q=3/t=1/n=5            | 1000   | 105.70 ms/op | 34.30 kB/op | 709764 allocs/op  |
| TTPKeygen/q=3/t=1/n=10           | 500    | 188.58 ms/op | 68.51 kB/op | 1417549 allocs/op |
|                                  |        |              |             |                   |
| Sign/pubM=1                      | 30000  | 2.65 ms/op   | 0.71 kB/op  | 14206 allocs/op   |
| Sign/pubM=3                      | 30000  | 2.44 ms/op   | 0.72 kB/op  | 14614 allocs/op   |
| Sign/pubM=5                      | 30000  | 2.46 ms/op   | 0.74 kB/op  | 15029 allocs/op   |
| Sign/pubM=10                     | 30000  | 2.72 ms/op   | 0.77 kB/op  | 16051 allocs/op   |
|                                  |        |              |             |                   |
| PrepareBlindSign/pubM=1/privM=3  | 2000   | 64.42 ms/op  | 18.26 kB/op | 366447 allocs/op  |
| PrepareBlindSign/pubM=3/privM=3  | 1000   | 73.21 ms/op  | 20.79 kB/op | 417517 allocs/op  |
| PrepareBlindSign/pubM=5/privM=3  | 1000   | 82.13 ms/op  | 23.32 kB/op | 468632 allocs/op  |
| PrepareBlindSign/pubM=10/privM=3 | 1000   | 102.95 ms/op | 29.66 kB/op | 596363 allocs/op  |
|                                  |        |              |             |                   |
| PrepareBlindSign/pubM=3/privM=1  | 3000   | 35.50 ms/op  | 10.61 kB/op | 212744 allocs/op  |
| PrepareBlindSign/pubM=3/privM=3  | 1000   | 73.21 ms/op  | 20.79 kB/op | 417517 allocs/op  |
| PrepareBlindSign/pubM=3/privM=5  | 1000   | 109.91 ms/op | 30.96 kB/op | 622296 allocs/op  |
| PrepareBlindSign/pubM=3/privM=10 | 500    | 200.21 ms/op | 56.40 kB/op | 1134289 allocs/op |
|                                  |        |              |             |                   |
| BlindSign/pubM=1/privM=3         | 1000   | 80.25 ms/op  | 19.80 kB/op | 395915 allocs/op  |
| BlindSign/pubM=3/privM=3         | 1000   | 94.95 ms/op  | 23.52 kB/op | 470805 allocs/op  |
| BlindSign/pubM=5/privM=3         | 1000   | 115.88 ms/op | 27.23 kB/op | 545636 allocs/op  |
| BlindSign/pubM=10/privM=3        | 500    | 151.66 ms/op | 36.52 kB/op | 732772 allocs/op  |
|                                  |        |              |             |                   |
| BlindSign/pubM=3/privM=1         | 2000   | 50.99 ms/op  | 13.12 kB/op | 262559 allocs/op  |
| BlindSign/pubM=3/privM=3         | 1000   | 94.95 ms/op  | 23.52 kB/op | 470805 allocs/op  |
| BlindSign/pubM=3/privM=5         | 1000   | 132.86 ms/op | 33.92 kB/op | 679003 allocs/op  |
| BlindSign/pubM=3/privM=10        | 500    | 224.29 ms/op | 59.92 kB/op | 1199647 allocs/op |
|                                  |        |              |             |                   |
| Unblind                          | 50000  | 2.23 ms/op   | 0.62 kB/op  | 12520 allocs/op   |
|                                  |        |              |             |                   |
| Verify/q=1                       | 2000   | 43.74 ms/op  | 16.68 kB/op | 377329 allocs/op  |
| Verify/q=3                       | 2000   | 58.98 ms/op  | 20.13 kB/op | 448605 allocs/op  |
| Verify/q=5                       | 2000   | 72.38 ms/op  | 23.57 kB/op | 519902 allocs/op  |
| Verify/q=10                      | 1000   | 99.86 ms/op  | 32.18 kB/op | 698113 allocs/op  |
|                                  |        |              |             |                   |
| ShowBlindSignature/privM=1       | 3000   | 25.86 ms/op  | 8.30 kB/op  | 170666 allocs/op  |
| ShowBlindSignature/privM=3       | 2000   | 46.45 ms/op  | 15.26 kB/op | 314652 allocs/op  |
| ShowBlindSignature/privM=5       | 2000   | 69.42 ms/op  | 22.22 kB/op | 458565 allocs/op  |
| ShowBlindSignature/privM=10      | 1000   | 122.28 ms/op | 39.63 kB/op | 818530 allocs/op  |
|                                  |        |              |             |                   |
| BlindVerify/pubM=1               | 2000   | 72.81 ms/op  | 25.04 kB/op | 548832 allocs/op  |
| BlindVerify/pubM=3               | 1000   | 95.70 ms/op  | 28.50 kB/op | 620468 allocs/op  |
| BlindVerify/pubM=5               | 1000   | 111.46 ms/op | 31.97 kB/op | 692124 allocs/op  |
| BlindVerify/pubM=10              | 1000   | 149.02 ms/op | 40.63 kB/op | 871100 allocs/op  |
|                                  |        |              |             |                   |
| Make Pi_S/privM=1                | 10000  | 11.69 ms/op  | 3.53 kB/op  | 70166 allocs/op   |
| Make Pi_S/privM=3                | 3000   | 29.47 ms/op  | 8.71 kB/op  | 174317 allocs/op  |
| Make Pi_S/privM=5                | 2000   | 47.39 ms/op  | 13.89 kB/op | 278486 allocs/op  |
| Make Pi_S/privM=10               | 1000   | 91.94 ms/op  | 26.85 kB/op | 538835 allocs/op  |
|                                  |        |              |             |                   |
| Verify Pi_S/privM=1              | 5000   | 19.90 ms/op  | 5.49 kB/op  | 109193 allocs/op  |
| Verify Pi_S/privM=3              | 2000   | 48.99 ms/op  | 13.29 kB/op | 265404 allocs/op  |
| Verify Pi_S/privM=5              | 1000   | 81.02 ms/op  | 21.08 kB/op | 421538 allocs/op  |
| Verify Pi_S/privM=10             | 500    | 157.98 ms/op | 40.58 kB/op | 811975 allocs/op  |
|                                  |        |              |             |                   |
| Make Pi_V/privM=1                | 10000  | 13.29 ms/op  | 4.21 kB/op  | 86467 allocs/op   |
| Make Pi_V/privM=3                | 3000   | 24.83 ms/op  | 7.73 kB/op  | 159146 allocs/op  |
| Make Pi_V/privM=5                | 3000   | 34.45 ms/op  | 11.24 kB/op | 231803 allocs/op  |
| Make Pi_V/privM=10               | 2000   | 62.37 ms/op  | 20.04 kB/op | 413538 allocs/op  |
|                                  |        |              |             |                   |
| Verify Pi_V/privM=1              | 5000   | 26.46 ms/op  | 8.28 kB/op  | 170223 allocs/op  |
| Verify Pi_V/privM=3              | 2000   | 41.59 ms/op  | 11.75 kB/op | 241841 allocs/op  |
| Verify Pi_V/privM=5              | 2000   | 63.44 ms/op  | 15.21 kB/op | 313454 allocs/op  |
| Verify Pi_V/privM=10             | 1000   | 100.71 ms/op | 23.87 kB/op | 492518 allocs/op  |

#### BLS381

todo
