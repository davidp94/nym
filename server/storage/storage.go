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

	"0xacab.org/jstuczyn/CoconutGo/common/comm/commands"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/util"
)

//
// Currently issuers store the following:
// [CREDENTIAL_PREFIX || BLOCK_HEIGHT || GAMMA] --- BLINDED_SIGNATURE
// [LATEST_STORED_KEY] - BLOCK_HEIGHT // used to indicate heighest processed block. It is guaranteed to be stored in order and hence there are no missing blocks before that.

var (
	credentialPrefix = []byte("CRED")
	latestStoredKey  = []byte("LATEST")
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

// FinalizeHeight increases the height of the latest processed block.
func (db *Database) FinalizeHeight(height int64) {
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, uint64(height))
	db.Set(latestStoredKey, val)
}

// even though we might have already stored all txs from the target height, we should not allow to access them
// unless we have processed all the blocks before it
func (db *Database) checkHeight(height int64) bool {
	curB := db.Get(latestStoredKey)
	cur := int64(binary.BigEndian.Uint64(curB))
	return cur >= height
}

// GetHighest obtains the height of the latest stored block. It's required on server restart.
func (db *Database) GetHighest() int64 {
	return int64(binary.BigEndian.Uint64(db.Get(latestStoredKey)))
}

// GetBlockCredentials gets all blinded signatures for given block height.
func (db *Database) GetBlockCredentials(height int64) []*commands.CredentialPair {
	if !db.checkHeight(height) {
		return nil
	}

	creds := []*commands.CredentialPair{}
	iter := db.db.NewIterator(util.BytesPrefix(credentialPrefix), nil)
	for iter.Next() {
		creds = append(creds, &commands.CredentialPair{
			Gamma:      iter.Key()[len(credentialPrefix)+8:],
			Credential: iter.Value(), // since it's a byte slice, it will be coppied
		})
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		panic(err)
	}

	// todo: cleanup sigs slice?
	return creds
}

// GetCredential gets credential at given height that used particular gamma.
func (db *Database) GetCredential(height int64, gammaB []byte) *commands.CredentialPair {
	key := make([]byte, len(credentialPrefix)+8+len(gammaB))
	copy(key, credentialPrefix)
	binary.BigEndian.PutUint64(key[len(credentialPrefix):], uint64(height))
	copy(key[len(credentialPrefix)+8:], gammaB)

	return &commands.CredentialPair{Gamma: gammaB, Credential: db.Get(key)}
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

	contains, err := db.Has(latestStoredKey, nil)
	if err != nil {
		return nil, err
	}
	if !contains {
		val := make([]byte, 8)
		binary.BigEndian.PutUint64(val, uint64(0))
		if err := db.Put(latestStoredKey, val, nil); err != nil {
			return nil, err
		}
	}

	database := &Database{
		db: db,
	}
	return database, nil
}
