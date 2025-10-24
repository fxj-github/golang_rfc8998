package main 

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

type Log struct {
	fatal *log.Logger
	warn *log.Logger
	info *log.Logger
	debug *log.Logger
	trace *log.Logger

	verbose int32
}

var (
	mu sync.Mutex
	logs = make(map[string]*Log)
)

func NewLog(name string) *Log {
	if len(name) == 0 {
		log.Fatal("Can not register empty name log\n")
	}

	prefix := name
	if !strings.HasPrefix(prefix, " ") {
		prefix = " " + prefix
	}
	if !strings.HasSuffix(prefix, " ") {
		prefix = prefix + " "
	}
	l := &Log{ fatal: log.New(os.Stdout, "F" + prefix, log.LstdFlags | log.Lmsgprefix | log.Lshortfile),
		warn: log.New(os.Stdout, "W" + prefix, log.LstdFlags | log.Lmsgprefix | log.Lshortfile),
		info: log.New(os.Stdout, "I" + prefix, log.LstdFlags | log.Lmsgprefix | log.Lshortfile),
		debug: log.New(os.Stdout, "D" + prefix, log.LstdFlags | log.Lmsgprefix | log.Lshortfile),
		trace: log.New(os.Stdout, "T" + prefix, log.LstdFlags | log.Lmsgprefix | log.Lshortfile),
		verbose: 2 }

	mu.Lock()
	if _, ok := logs[name]; ok {
		mu.Unlock()
		log.Fatalf("Can not register duplicated name: %s\n", name)
	}
	logs[name] = l 
	mu.Unlock()

	return l
}

func GetVerbose(name string) map[string]int32 {
	result := make(map[string]int32)

	mu.Lock()
	if len(name) == 0 {
		for k, v := range logs {
			result[k] = v.verbose
		}
		goto unlock
	}
	if v, ok := logs[name]; ok {
		result[name] = v.verbose
	}
unlock:
	mu.Unlock()

	return result
}

func SetVerbose(name string, verbose int32) {
	mu.Lock()
	defer mu.Unlock()

	if len(name) == 0 {
		for _, v := range logs {
			v.verbose = verbose
		}
		return
	}
	if v, ok := logs[name]; ok {
		v.verbose = verbose
	}
}

func (bl *Log) Fatal(format string, v ...interface{}) {
	if (bl.verbose >= 0) {
		bl.fatal.Output(2, fmt.Sprintf(format, v...))
	}
	os.Exit(1)
}

func (bl *Log) Warn(format string, v ...interface{}) {
	if (bl.verbose >= 1) {
		bl.warn.Output(2, fmt.Sprintf(format, v...))
	}
}

func (bl *Log) Info(format string, v ...interface{}) {
	if (bl.verbose >= 2) {
		bl.info.Output(2, fmt.Sprintf(format, v...))
	}
}

func (bl *Log) Debug(format string, v ...interface{}) {
	if (bl.verbose >= 3) {
		bl.debug.Output(2, fmt.Sprintf(format, v...))
	}
}

func (bl *Log) Trace(format string, v ...interface{}) {
	if (bl.verbose >= 4) {
		bl.trace.Output(2, fmt.Sprintf(format, v...))
	}
}
