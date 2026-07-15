package parser

import "network-compiler/internal/ir"

type Parser interface {
	ParseFile(path string) (ir.Device, error)
}
