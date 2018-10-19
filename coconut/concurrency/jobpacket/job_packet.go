package jobpacket

import (
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// todo make new jobpacket directly of op arguments and ch

type JobPacket struct {
	OutCh chan<- interface{}
	Op    func() (interface{}, error)
}

func MakeG1MulOp(g1 *Curve.ECP, x *Curve.BIG) func() (interface{}, error) {
	return func() (interface{}, error) {
		return Curve.G1mul(g1, x), nil
	}
}

func MakeG2MulOp(g2 *Curve.ECP2, x *Curve.BIG) func() (interface{}, error) {
	return func() (interface{}, error) {
		return Curve.G2mul(g2, x), nil
	}
}

// todo: remove pairing from BpGroup then?
func MakePairingOp(g1 *Curve.ECP, g2 *Curve.ECP2) func() (interface{}, error) {
	return func() (interface{}, error) {
		return Curve.Fexp(Curve.Ate(g2, g1)), nil
	}
}

// todo: is there any point in returning object rather than queing the packet straightaway?

func New(outCh chan<- interface{}, op func() (interface{}, error)) *JobPacket {
	return &JobPacket{
		OutCh: outCh,
		Op:    op,
	}
}
