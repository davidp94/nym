package coconut

import (
	"strings"

	"github.com/jstuczyn/CoconutGo/coconut/utils"
	"github.com/jstuczyn/amcl/version3/go/amcl"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

// getBaseFromAttributes generates the base h from public attributes.
// It is only used for Sign function that works exlusively on public attributes
// todo: actually logic in code is identical to constructChallenge in proofs
// (apart from SHA used) - combine them?
func getBaseFromAttributes(pubM []*Curve.BIG) *Curve.ECP {
	s := make([]string, len(pubM))
	for i := range pubM {
		s[i] = utils.ToCoconutString(pubM[i])
	}
	h, err := utils.HashStringToG1(amcl.SHA512, strings.Join(s, ","))
	if err != nil {
		panic(err)
	}
	return h
}
