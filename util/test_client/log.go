package main

import (
	"log/slog"
	"os"
	"sync"
)

var internalLevel *slog.LevelVar
var internalLogger *slog.Logger
var initialized sync.Once

const levelTrace = -8

func logger() *slog.Logger {
	initialized.Do(func() {
		internalLevel = new(slog.LevelVar)
		internalLevel.Set(slog.LevelInfo)

		internalLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: internalLevel,
		}))
	})
	return internalLogger
}

func setLogLevel(l slog.Level) {
	logger := logger()
	if logger == nil {
		return
	}
	internalLevel.Set(l)
}
