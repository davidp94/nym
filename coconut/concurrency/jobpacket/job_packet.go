package jobpacket

type JobPacket struct {
	OutCh chan<- interface{}
	Op    func() (interface{}, error)
}

func New(outCh chan<- interface{}, op func() (interface{}, error)) *JobPacket {
	return &JobPacket{
		OutCh: outCh,
		Op:    op,
	}
}
