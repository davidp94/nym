// currently this version does not include threshold credentials,
// this will be added in further iteration

package coconut

import (
	"fmt"

	"github.com/jstuczyn/CoconutGo/bpgroup"
	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/BLS381"
	// "github.com/milagro-crypto/amcl/version3/go/amcl/BN254"
)

// q is the number of attributes embedded in the credential
func Setup(q int) (*bpgroup.BpGroup, []*BLS381.ECP) {
	hs := make([]*BLS381.ECP, q)
	for i := 0; i < q; i++ {
		hn, err := hashToG1(amcl.SHA256, fmt.Sprintf("h%d", i))
		if err != nil {
			panic(err)
		}
		hs = append(hs, hn)
	}
	g := bpgroup.New()
	return g, hs
}

func Keygen() {

}
