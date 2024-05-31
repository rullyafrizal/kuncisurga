package kuncisurga

type Option func(g *Generator)

func WithBitSize(bitSize int) func(g *Generator) {
	return func(g *Generator) {
		g.BitSize = bitSize
	}
}
