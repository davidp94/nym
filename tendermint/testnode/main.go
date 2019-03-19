// main.go - starts a single tendermint node (+abci) used for testing
// Copyright (C) 2018-2019  Jedrzej Stuczynski.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"
)

const appAddrPort = "54320"
const appAddr = "tcp://127.0.0.1:54320"
const rpcAddr = "tcp://127.0.0.1:54321"
const p2pAddr = "tcp://127.0.0.1:54322"

const nodeDataDir = "node"
const appDataDir = "abci"

const tempABCIEntryPoint = "/home/jedrzej/go/src/0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/main.go"

const initialState = `  "app_state": {
    "accounts": [
      { 
        "address": "AxXOmCXFcuZKyKVhC3Vkoyewtydx7GPnqRF3zczVc1oBwSYb0+D1RxicnnsTvnGOUg==",
        "balance": 1000000
      },
      {
        "address": "AwCmV+emaAUznxv0pqe30qK4HaMzofY0cTM+upC0hKtJIGg58YJt26Ppqyl0L+9BXQ==",
        "balance": 42
      }
    ],
    "coconutProperties": {
      "q": 5,
      "threshold": 2,
      "issuingAuthorities": [
        {
          "id": 1,
          "vk": "CsABAkqisvCPCpEmCAUnLcUQUcbketT6QDsCtFELZHrj0XcLrAMmqAW779SAVsjBIb24E+ArYFJxn2B9rNOgiCdPZVlr0NCZILYatdphu9x/UEkzTPESE5RdV+WsfQVdBCt+DOXVJ3J9bhGMyc3G2i41Gq39m6qMvdOnbUKaaVFg0SySOsnMO6yiieGTVIYIuCgBBgbEoC6nNMwyrNKwK8KLmcs+KH6Fp2OvJnSSq1cumas/Nw0nXOwdoaqpB1/wX3m+EsABBZWuT/PRa4cz3Jui26fwRq2vkSDs2Bq+KhsxVqlhgbNk8bBqNrQuRO81iF19Lp+zDw2djCyMzmhOAGhGMuvnQ1xPZAn/PT7bsZH3BK9u/IR0O4DpW1O0x91dO/CmUXQNE12zqFGAhtyu2iQEv7L15Y+SzB4xOBaJU3t7+KQ8pY4zeqSzEZOIlL6+5QW7LGOxC4WpBr0JsVjGyqkHerm1jSLRYWbxC6m3sy66VrNsirCq55w5g213jsmXnEaqhshiGsABB6o6Iss5TE0qsG4qkU6A500qnhwkSgmW1wl+GjYDa1UHcx04L9YJAXr0ZygVTQm3CJ2nP1tjeSQRF7Gw056Bb5lIqhj2qqdLlw4/QZeL+ACtDCz5SR3yaFom7JPUlHJuDwlNdgwOCbw+yL4vYBYD7cqWDpGCxztJsM3pNjcVJ6zuNqT5IqXjTPdOrdhZ1tKpBxsqwYpMDGObqYCHy7jYkdUVwEbThzq1BkMu6Bq0bTW8y7l3a+PGZdsHej5aOukhGsABDugZL8mqReuuiJqVUuviKK9FeqIq4bstkJc4vfZAIst1F9FevVlXPJsozy1Knb+PBmnKqgV5qO+WjWY5+0qxKt49k1koS6id3AE4plc0US28olcpGMYwCsQ40d8zA2q8Es1XfqvZzGiR+i2czrru589hQDfEwVScuSodvCH8H4JPBvbV1L6QbyzxrYK6eyrHFLGVYGhJwAlDndzemIfGO0EnsQQu72cQaGtlP96QBPFe9lmwGLWyDSmTJFcMBdcBGsABEMVDkx0h472x6U/TITlfNVov0ROOWiPDvak+sDmuFdZpjRpYmG46/3kqXOqqneCcDykuhqd9NYp0g4QAQ6wlsioTGMynnD8ZXbLHjsy/bmMxUmcyKmilSR5/vfKbBIHeET95K5FVZ5Jwt+WjvUsToZgv906c/hbGwVDaWWybLkjMmavLKebcNCMlqMHlWQWeAWvc/FNX0DJQrrvuRNMcssv0NXjqKS2EkrTp7d2KN0nKgStEntVyFv/eJKEpzWAeGsABBXAljSl8L/kGDEQT3XXbvHfQwHpQp0Dr6iKOk1wGnsYyRWqh3xqEv1cxK/rRLCzzF2bu45XR7jR6exoyEXwZxWVjLoNH0dOX23wH8B0Wh66W3WFHLzdREDRZvf/5ZRycAJgOL/k+k6Zy0p4NPsxKOkBcsd99PYXdF1HeB5vZlRBo+3ia538JWnWusqTf5ACoBwgMpsJ7s6+D8R1Hrv0wkrPMEVNaZe4Cra72vxJh2aLyx1VDyB+E82XqDKGdWj2ZGsABGRNZtoLFElsjqDeK6wFdzpUPW/+Aok8vqvQ58J+kUzTu8aG7GKVBVMKmFpE5JPiPECuaJ/lVEMXrUWNhaFygtBZXyY4NzNlD0/JXbOSg1IledEE9rp1ZgV3BnDT0pNDvBzSSpdocd3lEwa+Vj3JW+dm6D5qpRvwZiJOhq0OO1hs1kB+jqlz/0JHgBKN6e8j2CUCy18862WXBC8Y3fxaZnULqI2fohIyeVtEe9JamEACF9rmtUB27W32tyxg64eZK",
          "pub_key" : "AwYXtM4pa4WV47TozIi1gf6t/jdRQyQkPv6mAC0S/fyzdPP4Pr3DAtOP0h0BYcHQIQ=="
        },
        {
          "id": 2,
          "vk": "CsABAkqisvCPCpEmCAUnLcUQUcbketT6QDsCtFELZHrj0XcLrAMmqAW779SAVsjBIb24E+ArYFJxn2B9rNOgiCdPZVlr0NCZILYatdphu9x/UEkzTPESE5RdV+WsfQVdBCt+DOXVJ3J9bhGMyc3G2i41Gq39m6qMvdOnbUKaaVFg0SySOsnMO6yiieGTVIYIuCgBBgbEoC6nNMwyrNKwK8KLmcs+KH6Fp2OvJnSSq1cumas/Nw0nXOwdoaqpB1/wX3m+EsABEziPTNnbFdWVKWnW9wrdHIfp5mBmP3Tly37adNJYkr7diE9GKYDk5ibP+05KU5pdDtM47jyd02lhPaJ7ba+ut3iwapOfHDYQY94s9MJeW4Oui9zO6Zqb1hQuGqrnyyU+GSwSHk6xERBG62RatHjhA+YED62K530BOGoEuNXWOicfB2yejusTYADfN8oMjqasDps589osO63PmHpMdqXG4kMBZdYpvnKvtUceXyo/TzJCYZi8jsq+v9PUuE/vfoVNGsABEzilZzpXO20TX85Pcee95NK8Uo6ComAoIR1OXkXtq4e71OWCQcKZ+cnlUq99v8Z5BwYZ4suQSNfX6luV+tk24+APcj4cE/pTmqjwr+30HiL4oJskwtKeO25XaJfJEGauBRPkPnoh+eDuqVn13XlpXLsvRHK+R4P5eO3w8YHStVxszNjXaoLZ8gHQOY0zpEh6E5fswq/S6PjFcY9hsTJME36tFQtGNZ7bmsc5lC9FbB4uhHFtWsEO3b5mue+AaJ3LGsABDKqVAVGqfHRpOqp/LzEcECsx2r5b4Iq2i40/JUQh3mHmxxq2/0dylBOaXvmP+weTD9VniUElMXHCRxvpf3dXtnnLWoC8lLOeDhF0M0mGoMJ2kaWoZpxnWQFIlC0YwzQqDVCbtoct2iVy9MUqgmVukgy6WOWYSrjxrygire3RWN/1QKo89bpMre+8MT/T3UnPFcpKvWQg1y6Oi9Icq+c2TBbbwxVOGh7lFUUCS3/iy6ZjR3VAxLJbUdhRu1tiv75sGsABF3ewbvXtxq4U824UaefaImE60mNlhwmLwMo9L3hAz4Zecyy4iHX+9lbAAKgHX0NgEmsYXDbyZOVvQHBV+VHhpqSYHlIEpafiwYaGj42brqeDECm+H/QqXTBkWMfuKiRUDw8OOnuViurz50sfGTcf6E4xGpW6HqCO9gsP8tbBmVV6aoraw5leSQpJG6ZDVs5YEWMKT+l2/7pbKoB/StmjYYGP58UFtQm5XqgbOgfEmqWCvNw6KKED/0o7cYus877GGsABB2AVuP6E3U/Ev/Mq8jDnS0Wt9JyhBHn1PkwJPuharNocTaUKEm0+roxTRLgbwZFeFCzDexlaUj357m3uiOrzcDIWFwLB0Cvluc9oxE5nWVfALbcVjX8mKXHbqrsi60nAFF0ZEQQBuhAngg71DohqJUyDcArrrlPelT0gj8dMoi46os4U9oSGQCQtQeAXOuhrFYgPcxOqjUN+0qvaZVbMNuBrEr59FJZHB7igIJEIomwjU18ifTLsqfMemRFZ0vIMGsABA4NqytB29r7T5Z7IeBPM9/b24DOTMI0AwMyo/i4Ef12n93dxWNPVY3Jgmqt1WjZyAXfQFVKzOsGvpUPaVl+HRvDfCXv3cHBpmELFA+3mNND557w6iRhSj5UoHqTzp+gXA4ppNKM33ZrEqHiZmbtFkJdzHXv2qSy2BCwNWOXJqom97kpU0xXUaS//snMGmLyzFUDGWUYKfGJe+rEx9A01xZpKxub2ejE1vkDI/szGo/iLsZ3vfFaBQT7ZY9JgdkrQ",
          "pub_key" : "AwPa/zgg0zxRdkISjUz7kHZmHyMPnDQmhhjDtnjG2Rgrx5EqjXAk0Lpgau0Z4+FsTA=="

        },
        {  
          "id": 3,
          "vk": "CsABAkqisvCPCpEmCAUnLcUQUcbketT6QDsCtFELZHrj0XcLrAMmqAW779SAVsjBIb24E+ArYFJxn2B9rNOgiCdPZVlr0NCZILYatdphu9x/UEkzTPESE5RdV+WsfQVdBCt+DOXVJ3J9bhGMyc3G2i41Gq39m6qMvdOnbUKaaVFg0SySOsnMO6yiieGTVIYIuCgBBgbEoC6nNMwyrNKwK8KLmcs+KH6Fp2OvJnSSq1cumas/Nw0nXOwdoaqpB1/wX3m+EsABB1IVntkheWq0Vq3vb1GSmESUS/uxTwHbeCs9E+FKE5mQGQbos1lcBuXnreqR4y96AC6FRas7hSeq4RV9NIrwHP8ophnzmFXjQHKizf4qV6jB1+AnZK153gbpIiezLah+C7ITrCUFgy7uwRCmXAsuxWPvxFE4HaT9az13vuvPSmi2l0Vsd8ZEHNdMPFgNYvPaFFibC0sqjK+M0/rrRsu1QhdmIhm9ZxBKqyDzCGa3KYZdrm39vmcVirdTolJXBM4HGsABCvs7qmHB5ROFpRAiTEHgZUR8gAxgK4OCu+tc0gvu1x8I1P0KQNJJ/GdMTSsUGv2FBbFeAq1LHxWra/txWnldIGTMhB14wKLcA60ww+yFGV7/RaO7db+qEazc2lEwe2z+ALtk9Unw6r2StvKQBNq0kdIW0I3v87asB5IFQvW+xNt4ftZsY67IK3UEJ/44JMToC7apDDekPulhmXS1kqfaVQVZNv3SZmLLkZk0AgGYzZowQS2WZe9Q5CUpj7gJtnncGsABD8Qqt3NjXLoPFxsUDV9317OYPV9iUmRepYVEyaXdEYlgcRU5atcjMX69IA6x/rooAXtHrjaX/4SkFt7AOU6GPmOGwnOW6b75yvQ2TS9mHYXzAb3B7lkfDtUDJkWoEDqmErNbM9bF6Kd4CC2adXvceLOkaQ/3PNoT60Pt1TKwZNQ23JHxzTDGipJVl3XW/RwJC7tMmDwPHycMs3vkFRHmnIy+XefouKzXnRy+AOoxWyNBRV8NzdmtF1ts8UIWaFw0GsABF/PBe2UMWA5tDNEJQR9RYLJhDBUMrKbnZkl+KHSpHAZrlOq6kiN4HiS3SfzPnDTMGIwDwDH3fCG5/PRvLrkbnIRSLpAvQZFxtaUWWLjN2emj5S4dYfwpjIUShlJgBFJzFqBQICgVTrtWVjcJeItFJGqBPS97f9cQlvrZAyvn/ZEEOOh9uKwavuExSP7W40R/BPQsUyo9Ji0IZVmeb51e7qoGbg/bCbHk/dAvuLL+stusb3nSOTtMG0FkTAq5kaXtGsABDRJ/+ITD+2on4ybD56k2I80PZ26DKHlaYnpgJYQgny6ksf/idhxmMEUX0uka2m8AAPC1UIVCaRmks85zAcmA48MmXtHUZFi0hrn9cu/hwP88GVzsNVNdyUBmkgxtYbVzD0l0BoqFSu71Ns0wxPCG/BQtS9GBBP8CftS7iXEhd6dll+bD4u19iUm1bsmPg0N9BSoUJsIIdDowQSzL/P9B6wdrKrQ0tNYwTFc5hI2wSOGAHrAvUHF4drpgp7fzRW/pGsABASzsxos6kwXY2PXW5rpUyelNO/PNLTr8j9VOrEBNNJE53EMk7wiJ+vfBe8ZHY5vHEdJs/SevVSqnrLqdeAAoKPfQVzxLmpO/Vm8CkXFj/NTw9CXvdXmqAlHD+hu5U1r7CtY4J4Ky3Qtdkh/drA2o+Ol7rUF3+Y6Iu7QaV6Edq7wi707BiAzQ7ju2WcaZ6BuBCqZa4pLOjplhiHIuJ0zvoWNvbIYfzy89ONODWDaNVN5gptj4Hs656agFLoKC2idm",
          "pub_key" : "Agj5NwcDaMIUMPVAV4BEzEkDJHo90WD36GRl43w8pDB9OZryEvPTNNZap+yuDD2zzg=="
        }
      ]
    }
  }
}`

// returns neccessary data in order to kill the node and do the cleanup
func startTestChain() (context.CancelFunc, string) {
	// func startTestChain(retCh chan struct{}) {
	tmpDir, err := ioutil.TempDir("", "tempTendermint")
	if err != nil {
		panic(err)
	}

	nodeData := path.Join(tmpDir, nodeDataDir)
	appData := path.Join(tmpDir, appDataDir)

	ctx, cancel := context.WithCancel(context.Background())

	exec.Command("tendermint", fmt.Sprintf("--home=%v", nodeData), "init").Run()
	fmt.Println(nodeData)

	// modify genesis to include initial state
	genFile, err := ioutil.ReadFile(path.Join(nodeData, "config", "genesis.json"))
	if err != nil {
		panic(err)
	}

	lines := strings.Split(string(genFile), "\n")

	// remove last line - closing tag
	lines = lines[:len(lines)-1]

	lines[len(lines)-1] = `  "app_hash": "",`

	stateLines := strings.Split(initialState, "\n")

	outGenesisLines := make([]string, len(lines)+len(stateLines))
	copy(outGenesisLines, lines)
	copy(outGenesisLines[len(lines):], stateLines)

	outGenesis := strings.Join(outGenesisLines, "\n")

	if err := ioutil.WriteFile(path.Join(nodeData, "config", "genesis.json"), []byte(outGenesis), 0644); err != nil {
		panic(err)
	}

	exec.CommandContext(ctx, "tendermint", "node",
		"--consensus.create_empty_blocks=false",
		"--home", nodeData,
		"--moniker=dummyTestNode",
		fmt.Sprintf("--proxy_app=%v", appAddr),
		"--log_level=state:info,*:error",
		fmt.Sprintf("--rpc.laddr=%v", rpcAddr),
		fmt.Sprintf("--p2p.laddr=%v", p2pAddr),
	).Start()

	exec.CommandContext(ctx, "go", "run", tempABCIEntryPoint,
		fmt.Sprintf("-port=%v", appAddrPort),
		fmt.Sprintf("-dbpath=%v", appData)).Start()

	return cancel, tmpDir
}

func main() {

	// ch := make(chan struct{})
	// // Setup the signal handling.
	haltCh := make(chan os.Signal)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)

	cancel, dataDir := startTestChain()

	defer os.RemoveAll(dataDir)

	<-haltCh
	cancel()
}
