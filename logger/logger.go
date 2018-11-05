package logger

import (
	"os"

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

// GetLogger returns a per-module logger that writes to the backend.
func (l *Logger) GetLogger(module string) *logging.Logger {
	log := logging.MustGetLogger(module)
	log.SetBackend(l.backend)
	return log
}

// New returns new instance of logger
func New() *Logger {
	// for now just constant formatting string; taken from library example
	logFmt := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{module}/%{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`)

	// right now just log everything to stderr, later it's easy to adjust to make it log to a file instead

	base := logging.NewLogBackend(os.Stderr, "", 0)
	formatted := logging.NewBackendFormatter(base, logFmt)
	backend := logging.AddModuleLevel(formatted)
	// logging.SetBackend(formatted) // needed?
	return &Logger{
		backend: backend,
	}
}
