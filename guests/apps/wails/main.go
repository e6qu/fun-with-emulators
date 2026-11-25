// A Wails app of fwe's own: one window showing dist/index.html, which the
// application tests look at. Built under fwe on an Alpine root, offline,
// from the modules go.sum pins:
//
//	go build -buildmode=pie -tags desktop,production,webkit2_41
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:dist
var assets embed.FS

func main() {
	err := wails.Run(&options.App{
		Title:       "fwe-wails",
		Width:       800,
		Height:      600,
		AssetServer: &assetserver.Options{Assets: assets},
	})
	if err != nil {
		panic(err)
	}
}
