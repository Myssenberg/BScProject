from zksk import Secret, DLRep
from zksk.composition import OrProofStmt
from zksk.primitives.dl_notequal import DLNotEqual
from zksk.utils.groups import make_generators
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc


group, g, order, pk, sk = keygen()

m = Secret(name="m", value=2)
r = Secret(name="r", value=order.random())

c0, c1 = enc(g, order, pk, m.value, r.value)

enc_stmt = DLRep(c0, r*g) & DLRep(c1, m*g + r*pk)

####
_, pk = make_generators(2, group)

r = order.random()

a = 1

C = (a+r)*pk


y1 = m.value*g
y2 = 1*g

neq_stmt = DLNotEqual((y1, g), (y2, g), m, bind=True) #Somehow not working for only two candidates

stmt = enc_stmt & neq_stmt

nizk = stmt.prove({m: m.value, r: r.value})
v = stmt.verify(nizk)
print("Proof verified: ", v)