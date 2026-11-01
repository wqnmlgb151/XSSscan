//go:build !windows

package privatefs

import "os"

func createFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}

func createDir(path string) error { return os.Mkdir(path, 0700) }
