from zksk import Secret, DLRep, utils
from zksk.composition import OrProofStmt
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc

#Bob Keygen
group, g, order, pk, sk = keygen()

#Alice encryption
m = Secret(name="m", value=1)
r = Secret(name="r", value=order.random())
c = enc(g, order, pk, m.value, r.value)
c0, c1 = c

#print("C1 type: ", type(c1))


#Bob decryption
x = Secret(name="x", value=sk)
m_dec = dec(c, x.value)

#print("c0*x type: ", type(c0*x))

one = Secret(name="one", value=1)
neg_x = Secret(name="neg_x", value = -sk)

dec_stmt = DLRep(m_dec, one*c1 + neg_x*c0)

nizk = dec_stmt.prove({neg_x: neg_x.value})
v = dec_stmt.verify(nizk)
print(v)


# THINGS I TRIED:
#neg_x = Secret(name="neg_x", value=-1)*x
#neg = Secret(name="neg", value=-1)
#c0prime = (-1)*c0
#neg_one = bn.Bn(-1).mod(order)