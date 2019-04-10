// storage.go - Database connector.
// Copyright (C) 2019  Jedrzej Stuczynski.
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

// Package storage implements an interface to a goleveldb database.
package storage

import (
	"bytes"
	"encoding/binary"
	"path/filepath"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/util"
)

//
// Currently issuers store the following:
// [CREDENTIAL_PREFIX || BLOCK_HEIGHT || GAMMA] --- BLINDED_SIGNATURE
// [BLOCK_STATUS_PREFIX || BLOCK_HEIGHT] --- 0/1 // required if client requested entire block of signatures while processing the particular block

var (
	credentialPrefix  = []byte("CRED")
	blockStatusPrefix = []byte("STAT")
)

// Database represents all data required to interact with the storage.
type Database struct {
	db *leveldb.DB
}

// Get gets the value corresponding to particular key. Returns nil if it doesn't exist.
func (db *Database) Get(key []byte) []byte {
	key = nonNilBytes(key)
	res, err := db.db.Get(key, nil)
	if err != nil {
		if err == errors.ErrNotFound {
			return nil
		}
		panic(err)
	}
	return res
}

// Set sets particular key value pair.
func (db *Database) Set(key []byte, value []byte) {
	key = nonNilBytes(key)
	value = nonNilBytes(value)
	err := db.db.Put(key, value, nil)
	if err != nil {
		panic(err)
	}
}

// StoreBlindedSignature stores particular blinded signature using appropriate key.
func (db *Database) StoreBlindedSignature(height int64, gammaB []byte, sig []byte) {
	key := make([]byte, len(credentialPrefix)+8+len(gammaB))
	copy(key, credentialPrefix)
	binary.BigEndian.PutUint64(key[len(credentialPrefix):], uint64(height))
	copy(key[len(credentialPrefix)+8:], gammaB)

	contains, err := db.db.Has(key, nil)
	if err != nil {
		panic(err)
	}
	// there is already a blinded signature for this particular entry
	if contains {
		// but if for some reason it's identical as what we wanted to write
		// (which in theory shouldn't have been invoked in the first place), just ignore it
		if bytes.Compare(sig, db.Get(key)) == 0 {
			return
		}
		// otherwise include a suffix in the entry which is up to the client to decode and try again
		db.StoreBlindedSignature(height, append(gammaB, 0), sig)
	}
}

// FinalizeHeight sets a flag on given block height to indicate all txs from that height were processed.
func (db *Database) FinalizeHeight(height int64) {
	key := make([]byte, len(blockStatusPrefix)+8)
	copy(key, blockStatusPrefix)
	binary.BigEndian.PutUint64(key[len(blockStatusPrefix):], uint64(height))
	db.Set(key, []byte{1})
}

// GetBlockCredentials gets all blinded signatures for given block height.
func (db *Database) GetBlockCredentials(height int64) [][]byte {
	key := make([]byte, len(blockStatusPrefix)+8)
	copy(key, blockStatusPrefix)
	binary.BigEndian.PutUint64(key[len(blockStatusPrefix):], uint64(height))
	contains, err := db.db.Has(key, nil)
	if err != nil {
		panic(err)
	}
	if !contains {
		return nil
	}

	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, uint64(height))

	sigs := [][]byte{}
	iter := db.db.NewIterator(util.BytesPrefix(heightBytes), nil)
	for iter.Next() {
		sig := iter.Value()
		sigCpy := make([]byte, len(sig))
		copy(sigCpy, sig)
		sigs = append(sigs, sig)
	}
	iter.Release()
	if err = iter.Error(); err != nil {
		panic(err)
	}

	// todo: cleanup sigs slice?
	return sigs
}

// GetCredential gets credential at given height that used particular gamma.
func (db *Database) GetCredential(height int64, gammaB []byte) []byte {
	key := make([]byte, len(credentialPrefix)+8+len(gammaB))
	copy(key, credentialPrefix)
	binary.BigEndian.PutUint64(key[len(credentialPrefix):], uint64(height))
	copy(key[len(credentialPrefix)+8:], gammaB)

	return db.Get(key)
}

// Close closes the database connection. It should be called upon server shutdown.
func (db *Database) Close() {
	db.db.Close()
}

func nonNilBytes(bz []byte) []byte {
	if bz == nil {
		return []byte{}
	}
	return bz
}

// New returns new instance of a database.
func New(name string, dir string) (*Database, error) {
	dbPath := filepath.Join(dir, name+".db")
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	database := &Database{
		db: db,
	}
	return database, nil
}
