from bplib.bp import BpGroup, G2Elem, G1Elem
from petlib.bn import Bn, force_Bn
import petlib.pack
from coconut.utils import *
from coconut.proofs import *
from coconut.scheme import *
import struct
from binascii import hexlify

def generateData():
	G = BpGroup()
	(g1, g2, o) = G.gen1(), G.gen2(), G.order()
	hex_m = "1D70206E93922A266B6F522CB1EC8AA72F908AC87EED1E43C641BFAF3C82AC32" # generated in previous run
	hex_x = "076501B5E73FA81B28FAB06EE3F6929E6AE4DB9461A49930C49EF1B28A625DD2" # generated in previous run
	hex_y = "0CE30F26C29ADBE06AE98D9B49DB3FF323C8100072298E9A58AC347E9BE59F36" # generated in previous run
	hex_h = "021c1dbf7bdc24be8d2b5c56d7a3162a9a1ef824134c3a95b6d306ecd8ce90c193" # generated in previous run (random * g1)

	x = Bn.from_hex(hex_x)
	y = Bn.from_hex(hex_y)
	m = Bn.from_hex(hex_m)

	h = G1Elem.from_bytes(bytes.fromhex(hex_h), G)
	# simple Pointcheval-Sanders signature on single public attribute
	sig = (x + y * m) * h

	print(hexlify(h.export()))
	print("")
	print(hexlify(sig.export()))


if __name__ == "__main__":
    generateData()