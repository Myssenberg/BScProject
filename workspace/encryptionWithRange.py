from zksk import Secret, DLRep
from zksk.composition import OrProofStmt
from zksk.primitives.rangeproof import RangeStmt
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc

group, g, order, pk, sk = keygen()

m = Secret() #value = 2
r = Secret(value = order.random()) #value = order.random()

m_value = 2
r_value = order.random()

c0, c1 = enc(g, order, pk, m_value, r.value)

enc_stmt = DLRep(c0, r*g) & DLRep(c1, m*g + r*pk)

range_stmt = RangeStmt(c1, g, pk, 0, 3, m, r) #Somehow not working for only two candidates

stmt = enc_stmt & range_stmt

nizk = stmt.prove({m: m_value, r: r.value})
v = stmt.verify(nizk)
print("Proof verified: ", v)


"""
group, g, order, pk, sk = keygen()

m = Secret(name="m", value=2)
r = Secret(name="r", value=order.random())

c0, c1 = enc(g, order, pk, m.value, r.value)

enc_stmt = DLRep(c0, r*g) & DLRep(c1, m*g + r*pk)

range_stmt = RangeStmt(c1, g, pk, 0, 3, m, r) #Somehow not working for only two candidates

stmt = enc_stmt & range_stmt

nizk = stmt.prove({m: m.value, r: r.value})
v = stmt.verify(nizk)
print("Proof verified: ", v)
"""