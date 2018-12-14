// logger_test.go - tests for logger
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
package logger

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/op/go-logging.v1"
)

func TestLogLevelFromString(t *testing.T) {
	levels := []struct {
		str   string // pointer is used so that nil values could be tested
		level logging.Level
		err   error
	}{
		{str: "CRITICAL", level: logging.CRITICAL, err: nil},
		{str: "ERROR", level: logging.ERROR, err: nil},
		{str: "WARNING", level: logging.WARNING, err: nil},
		{str: "NOTICE", level: logging.NOTICE, err: nil},
		{str: "INFO", level: logging.INFO, err: nil},
		{str: "DEBUG", level: logging.DEBUG, err: nil},

		{str: "critical", level: logging.CRITICAL, err: nil},
		{str: "ERRor", level: logging.ERROR, err: nil},
		{str: "warnING", level: logging.WARNING, err: nil},
		{str: "NoTiCe", level: logging.NOTICE, err: nil},

		{str: "", level: logging.ERROR, err: logging.ErrInvalidLogLevel},
		{str: "warn", level: logging.ERROR, err: logging.ErrInvalidLogLevel},
		{str: "ńótićę", level: logging.ERROR, err: logging.ErrInvalidLogLevel},
	}

	for _, l := range levels {
		lev, err := logLevelFromString(l.str)
		assert.Equal(t, lev, l.level)
		assert.Equal(t, err, l.err)
	}
}

func TestNew(t *testing.T) {
	validLevel := "NOTICE" // we don't need to test it as it was done above

	tmpfile, err := ioutil.TempFile("", "tmplog")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	tests := []struct {
		f       string
		disable bool

		isValid bool
	}{
		{f: "someinvalidnotexistingpath/", disable: false, isValid: false},

		{f: "", disable: true, isValid: true},
		// if it disabled, we shouldn't need to care about the rest
		{f: "someinvalidnotexistingpath/", disable: true, isValid: true},
		{f: tmpfile.Name(), disable: false, isValid: true},
		{f: tmpfile.Name(), disable: true, isValid: true},
	}

	for _, test := range tests {
		if err := os.Truncate(tmpfile.Name(), 0); err != nil {
			log.Fatal(err)
		}

		logger, err := New(test.f, validLevel, test.disable)
		if test.isValid {
			assert.NotNil(t, logger)
			assert.Nil(t, err)
		} else {
			assert.Nil(t, logger)
			assert.Error(t, err)
		}

		if test.f == tmpfile.Name() && !test.disable {
			logger.GetLogger("test").Notice("Test log")

			file, err := os.Open(tmpfile.Name())
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			scanner.Scan()
			written := scanner.Text()
			assert.True(t, strings.HasSuffix(written, "Test log"))
		}

	}

}
