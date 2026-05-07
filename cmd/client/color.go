package main

import "os"

func shouldUseColor(out *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	if force := os.Getenv("FORCE_COLOR"); force != "" && force != "0" {
		return true
	}

	info, err := out.Stat()
	if err != nil {
		return false
	}

	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}

	return platformColorSupported(out)
}
