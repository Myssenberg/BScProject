from zksk import Secret, DLRep
from zksk.composition import OrProofStmt
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc


group, g, order, pk, sk = keygen()

m = Secret(name="m", value=1)
r = Secret(name="r", value=order.random())

c0, c1 = enc(g, order, pk, m.value, r.value)

enc_stmt = DLRep(c0, r*g) & DLRep(c1, m*g + r*pk)

nizk = enc_stmt.prove({m: m.value, r: r.value})
v = enc_stmt.verify(nizk)
print(v)