from zksk import Secret, DLRep, utils
from zksk.composition import OrProofStmt
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc, re_enc

#Bob Keygen
group, g, order, pk, sk = keygen()

#Alice encryption
m = Secret(name="m", value=1)
r = Secret(name="r", value=order.random())
c = enc(g, order, pk, m.value, r.value)
c0, c1 = c

#Bob re-encryption
rPrime = Secret(name="rPrime", value=order.random())

reEnc = re_enc(g, order, pk, c, rPrime.value)

c0Prime, c1Prime = reEnc

dec_stmt = DLRep(c0Prime, c0 + rPrime*g) & DLRep(c1Prime, c1 + rPrime*pk) # Should maybe be (c1 & c2) & (c1' & c2')

nizk = dec_stmt.prove({rPrime: rPrime.value})
v = dec_stmt.verify(nizk)
print(v)