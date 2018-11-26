// cryptoworker.go - Coconut Worker for Coconut client.
// Copyright (C) 2018  Jedrzej Stuczynski.
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

// todo: description
package cryptoworker

import (
	"github.com/jstuczyn/CoconutGo/logger"
	"gopkg.in/op/go-logging.v1"

	"fmt"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/concurrency/coconutworker"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
)

// Worker allows writing coconut actions to a shared job queue,
// so that they could be run concurrently.
type Worker struct {
	cw  *coconutworker.Worker
	log *logging.Logger
	id  uint64
}

func (w *Worker) CoconutWorker() *coconutworker.Worker {
	return w.cw
}

// New creates new instance of a coconutWorker.
// nolint: lll
func New(jobQueue chan<- interface{}, id uint64, l *logger.Logger, params *coconut.Params) *Worker {
	cw := coconutworker.New(jobQueue, params)

	w := &Worker{
		cw:  cw,
		log: l.GetLogger(fmt.Sprintf("Clientcryptoworker:%d", int(id))),
		id:  id,
	}

	// no need of having a forever loop
	return w
}
