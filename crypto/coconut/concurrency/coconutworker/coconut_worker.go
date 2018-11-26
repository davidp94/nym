// performs coconut operations
package coconutworker

import (
	"sync"

	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	"github.com/jstuczyn/CoconutGo/crypto/elgamal"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// Worker allows writing coconut actions to a shared job queue,
// so that they could be run concurrently.
type Worker struct {
	jobQueue  chan<- interface{}
	muxParams *MuxParams
}

func (cw *Worker) SignWrapper(sk *coconut.SecretKey, pubM []*Curve.BIG) (*coconut.Signature, error) {
	return cw.Sign(cw.muxParams, sk, pubM)
}

func (cw *Worker) BlindSignWrapper(sk *coconut.SecretKey, blindSignMats *coconut.BlindSignMats, egPub *elgamal.PublicKey, pubM []*Curve.BIG) (*coconut.BlindedSignature, error) {
	return cw.BlindSign(cw.muxParams, sk, blindSignMats, egPub, pubM)
}

func (cw *Worker) VerifyWrapper(vk *coconut.VerificationKey, pubM []*Curve.BIG, sig *coconut.Signature) bool {
	return cw.Verify(cw.muxParams, vk, pubM, sig)
}

func (cw *Worker) BlindVerifyWrapper(vk *coconut.VerificationKey, sig *coconut.Signature, blindShowMats *coconut.BlindShowMats, pubM []*Curve.BIG) bool {
	return cw.BlindVerify(cw.muxParams, vk, sig, blindShowMats, pubM)
}

func (cw *Worker) AggregateVerificationKeysWrapper(vks []*coconut.VerificationKey, pp *coconut.PolynomialPoints) *coconut.VerificationKey {
	return cw.AggregateVerificationKeys(cw.muxParams, vks, pp)
}

func (cw *Worker) AggregateSignaturesWrapper(sigs []*coconut.Signature, pp *coconut.PolynomialPoints) *coconut.Signature {
	return cw.AggregateSignatures(cw.muxParams, sigs, pp)
}

// New creates new instance of a coconutWorker.
func New(jobQueue chan<- interface{}, params *coconut.Params) *Worker {
	muxParams := &MuxParams{params, sync.Mutex{}}
	cw := &Worker{
		jobQueue:  jobQueue,
		muxParams: muxParams,
	}

	return cw
}
