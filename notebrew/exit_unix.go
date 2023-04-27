//go:build !windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func exit(v ...any) {
	if len(v) == 0 {
		os.Exit(0)
	}
	err, ok := v[0].(error)
	if ok {
		if errors.Is(err, flag.ErrHelp) || errors.Is(err, io.EOF) {
			os.Exit(0)
		}
	}
	fmt.Println(v...)
	os.Exit(1)
}
