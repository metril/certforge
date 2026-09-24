//go:build !embedweb

package webui

import (
	"embed"
	"io/fs"
)

//go:embed placeholder
var placeholder embed.FS

func assets() fs.FS {
	sub, err := fs.Sub(placeholder, "placeholder")
	if err != nil {
		panic(err)
	}
	return sub
}
