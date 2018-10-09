from bplib.bp import BpGroup, G2Elem, G1Elem
from petlib.bn import Bn, force_Bn
import petlib.pack
from coconut.utils import *
from coconut.proofs import *
from coconut.scheme import *
import struct
from binascii import hexlify

def printBn(bn):
	print(bn.hex())

def printEC(ec):
	print(hexlify(ec.export()))


# modified version with additional arguments to remove randomness
# and allow comparison with go implementation
def make_pi_s_witn(witnesses, params, gamma, ciphertext, cm, k, r, public_m, private_m):
	(wr, wk, wm) = witnesses
	(G, o, g1, hs, g2, e) = params
	attributes = private_m + public_m
	h = G.hashG1(cm.export())
	Aw = [wki*g1 for wki in wk]
	Bw = [wk[i]*gamma + wm[i]*h for i in range(len(private_m))]
	Cw = wr*g1 + ec_sum([wm[i]*hs[i] for i in range(len(attributes))])
	c = to_challenge([g1, g2, cm, h, Cw]+hs+Aw+Bw)
	rr = (wr - c * r) % o
	rk = [(wk[i] - c*k[i]) % o for i in range(len(wk))]
	printBn(wk[0])
	printBn(rk[1])
	rm = [(wm[i] - c*attributes[i]) % o for i in range(len(wm))]
	return (c, rk, rm, rr)


# modified version with additional arguments to remove randomness
# and allow comparison with go implementation
def elgamal_enc_k(params, gamma, m, h, k):
	(G, o, g1, hs, g2, e) = params
	a = k * g1
	b = k * gamma + m * h
	return (a, b, k)

# modified version with additional arguments to remove randomness
# and allow comparison with go implementation
def prepare_blind_sign_r(r, ks, witnesses, params, gamma, private_m, public_m=[]):
	(G, o, g1, hs, g2, e) = params
	attributes = private_m + public_m
	cm = r*g1 + ec_sum([attributes[i]*hs[i] for i in range(len(attributes))])
	h = G.hashG1(cm.export()) 
	enc = [
		elgamal_enc_k(params, gamma, private_m[0], h, ks[0]),
		elgamal_enc_k(params, gamma, private_m[1], h, ks[1])
	]
	(a, b, k) = zip(*enc)
	c = list(zip(a, b))
	pi_s = make_pi_s_witn(witnesses, params, gamma, c, cm, k, r, public_m, private_m)
	return (cm, c, pi_s)

def generateData():
	params = setup(4)
	(G, o, g1, hs, g2, e) = params

	hex_m_priv1 = "24ABEE7D59CA09122391B3ECCBEBE0FA79EB9954D0E9F139A2A6E129445F1208" 
	hex_m_priv2 = "1B4A6A9A72935D4D3CBCDEA5143480C543E9F3F0C91787605220BF54EC4E6078"
	hex_m_pub1 = "1D70206E93922A266B6F522CB1EC8AA72F908AC87EED1E43C641BFAF3C82AC32"
	hex_m_pub2 = "0F6EE88081A8A94677A8993F85245C30106B1A8E794496276B1452915F4BB708"
	hex_x = "076501B5E73FA81B28FAB06EE3F6929E6AE4DB9461A49930C49EF1B28A625DD2" 
	hex_y0 = "0CE30F26C29ADBE06AE98D9B49DB3FF323C8100072298E9A58AC347E9BE59F36" 
	hex_y1 = "09BD32C15ED60E7C9E5EC7FD2D3294D712DDC0AE510071D3AD9CE3DE0F1F23C1"
	hex_y2 = "0CF37DAD7889F0959E571D79532CD1E3AE74BD2B26C78D68251EDB7685782B9E"
	hex_y3 = "07712709AED9F065B553E08267EA9A5C75D0B4F62DE110569BF350E8BDC0F980"
	hex_h = "021c1dbf7bdc24be8d2b5c56d7a3162a9a1ef824134c3a95b6d306ecd8ce90c193" # (random * g1) (for Pointcheval)
	hex_d = "1CF5133799A1CB2A1A46DD3FA5CB1EA9069D022236747F1CCA77401A265CEA33"
	hex_r = "24338A5F29CAB6BD573F87D5E2E6DDCFFB55CDB55D03A40A828A061E0E9957CE"
	hex_k1 = "077CA2D8137CA54B12011E564BA9B4204ADECA64499D07EE02DE6420E8B058A8"
	hex_k2 = "12B9BD2873FD1BA68D0B61A9B6840CA920C493D54CE85E8C2143C12F144C3B26"
	hex_wr = "1D7A898A391A664BAF3146F7ACA1FC0E954ED426ACD2D50146997A94053DCF6A"
	hex_wk1 = "0AF5628DF706A6CF503237499F793ABBDF4379DE3EF2D3DE777F4AB32B3147BD"
	hex_wk2 = "0E093B9EE3273CFB42C2765A0D78EF4EBD40126DC1703A921680EAA4CF50814D"
	hex_wm1 = "1DA762D767AD63BD4226CC6E859FC376CA03A047E47B82AFE8574D93DF39B5BB"
	hex_wm2 = "11A4B4BF934A3709F9E7A54324AACF0ED13BCAAA0CC2AD2791437363A64E404C"
	hex_wm3 = "096EB6930E70DEE0ACC0093A23A3586217C20FD6FD1ECB9923B2EDCE288F961F"
	hex_wm4 = "131CCECB6386CA3A773C898193116B76A2D6BD34D3BB4A7BC7143E494B7C69D9"


	# elgamal keypair
	d = Bn.from_hex(hex_d)
	gamma = g1 * d

	# attributes to sign
	private_m = [Bn.from_hex(hex_m_priv1), Bn.from_hex(hex_m_priv2)]
	public_m = [Bn.from_hex(hex_m_pub1), Bn.from_hex(hex_m_pub2)]

	# coconut keys
	x = Bn.from_hex(hex_x)
	y = [Bn.from_hex(hex_y0), Bn.from_hex(hex_y1), Bn.from_hex(hex_y2), Bn.from_hex(hex_y3)]
	beta = [g2*y[0], g2*y[1], g2*y[2], g2*y[3]]
	sk = (x, y)
	vk = (g2, g2*x, beta)

	r = Bn.from_hex(hex_r)
	ks = [Bn.from_hex(hex_k1), Bn.from_hex(hex_k2)]

	# create the witnesses
	wr = Bn.from_hex(hex_wr)
	wk = [Bn.from_hex(hex_wk1), Bn.from_hex(hex_wk2)]
	wm = [Bn.from_hex(hex_wm1), Bn.from_hex(hex_wm2), Bn.from_hex(hex_wm3), Bn.from_hex(hex_wm4)]
	witnesses = (wr, wk, wm)	

	(cm, c, pi_s) = prepare_blind_sign_r(r, ks, witnesses, params, gamma, private_m, public_m=public_m)

	(ch, rk, rm, rr) = pi_s


	
	# sigma_tilde = blind_sign(params, sk, cm, c, gamma, pi_s, public_m=public_m) 
	# sig = unblind(params, sigma_tilde, d)
	# sigma = randomize(params, sig)
	# (kappa, nu, pi_v) = show_blind_sign(params, vk, sigma, private_m)
	# assert blind_verify(params, vk, sigma, kappa, nu, pi_v, public_m=public_m)


if __name__ == "__main__":
    generateData()