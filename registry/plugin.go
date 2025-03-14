package registry

import (
	"os"
)

// AnalysisPlugins is the iterable collection of all active plugins
var AnalysisPlugins []AnalysisPlugin

// AnalysisPlugin defines the high level functions every EnrichPlugin has to
// provide.
type AnalysisPlugin interface {
	Name() string
	ReInitialize() error
	ProcessFile(FileSample) (string, bool, error)
}

// RegisterAnalysisPlugin makes an enrichment plugin available for usage
func RegisterAnalysisPlugin(p AnalysisPlugin) {
	AnalysisPlugins = append(AnalysisPlugins, p)
}

// FileSample is the struct passed to every plugin to handle the sample
type FileSample struct {
	FD       uintptr
	Info     os.FileInfo
	OrigPath string
}
