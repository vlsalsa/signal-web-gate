package main

import (
	"io"
	"log"
	"os"
	"sync"
)

var logMu sync.Mutex

func captureLog(w io.Writer) io.Writer { log.SetOutput(w); return os.Stderr }
func restoreLog(w io.Writer)           { log.SetOutput(w) }
