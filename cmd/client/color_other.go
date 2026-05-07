//go:build !windows

package main

import "os"

func platformColorSupported(_ *os.File) bool {
	return true
}
