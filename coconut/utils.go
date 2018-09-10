package coconut

import (
	"errors"

	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
)

func hashToG1(sha int, m string) (*BLS381.ECP, error) {
	b := []byte(m)
	// below is based on the amcl implementation: https://github.com/milagro-crypto/amcl/blob/22f62d8215adf5672017c11d2f6885afb00268c4/version3/go/MPIN.go#L83
	var R []byte

	if sha == amcl.SHA256 {
		H := amcl.NewHASH256()
		H.Process_array(b)
		R = H.Hash()
	}
	if sha == amcl.SHA384 {
		H := amcl.NewHASH384()
		H.Process_array(b)
		R = H.Hash()
	}
	if sha == amcl.SHA512 {
		H := amcl.NewHASH512()
		H.Process_array(b)
		R = H.Hash()
	}
	// create inf elem
	if R == nil {
		return nil, errors.New("Nil hash result")
	}

	const RM int = int(BLS381.MODBYTES)
	var W [RM]byte
	if sha >= RM {
		for i := 0; i < RM; i++ {
			W[i] = R[i]
		}
	} else {
		for i := 0; i < sha; i++ {
			W[i+RM-sha] = R[i]
		}
		for i := 0; i < RM-sha; i++ {
			W[i] = 0
		}
	}
	return BLS381.ECP_mapit(W[:]), nil
}
