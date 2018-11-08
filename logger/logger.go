package logger

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/op/go-logging.v1"
)

// log.Debugf("debug %s", Password("secret"))
// log.Info("info")
// log.Notice("notice")
// log.Warning("warning")
// log.Error("err")
// log.Critical("crit")

// Logger struct is self-explanatory
type Logger struct {
	backend logging.LeveledBackend
}

func logLevelFromString(l string) (logging.Level, error) {
	switch strings.ToUpper(l) {
	case "ERROR":
		return logging.ERROR, nil
	case "WARNING":
		return logging.WARNING, nil
	case "NOTICE":
		return logging.NOTICE, nil
	case "INFO":
		return logging.INFO, nil
	case "DEBUG":
		return logging.DEBUG, nil
	default:
		return logging.CRITICAL, fmt.Errorf("log: invalid level: '%v'", l)
	}
}

// GetLogger returns a per-module logger that writes to the backend.
func (l *Logger) GetLogger(module string) *logging.Logger {
	log := logging.MustGetLogger(module)
	log.SetBackend(l.backend)
	return log
}

// New returns new instance of logger
func New(f string, level string, disable bool) *Logger {
	// for now just constant formatting string; taken from library example
	logFmt := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{module}/%{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`)

	lvl, err := logLevelFromString(level)
	if err != nil {
		return nil
	}

	var logOut io.Writer
	if disable {
		logOut = ioutil.Discard
	} else if f == "" {
		logOut = os.Stdout
	} else {
		const fileMode = 0600

		var err error
		flags := os.O_CREATE | os.O_APPEND | os.O_WRONLY
		logOut, err = os.OpenFile(f, flags, fileMode)
		if err != nil {
			fmt.Printf("server: failed to create log file: %v", err)
			return nil
		}
	}

	base := logging.NewLogBackend(logOut, "", 0)
	formatted := logging.NewBackendFormatter(base, logFmt)
	backend := logging.AddModuleLevel(formatted)
	// logging.SetBackend(formatted) // needed?
	logging.SetLevel(lvl, "")

	return &Logger{
		backend: backend,
	}
}
