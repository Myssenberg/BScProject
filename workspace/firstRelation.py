from zksk import Secret, DLRep, utils
from zksk.composition import OrProofStmt
from zksk.primitives.rangeproof import RangeStmt
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc, re_enc

#Voter generates own sk og pk
group, g, order, pk_id, sk_id = keygen()


#Program generates other sks and pks, but voter only knows pks
sk_T = order.random() #Tallier
pk_T = sk_T*g

sk_vs = order.random() #Voting server
pk_vs = sk_vs*g


#Voter witnesses
sk = Secret()
r_1 = Secret()
v = Secret()
r_2 = Secret()
lv = Secret()
r_3 = Secret()

#First proof of encryption
v.value = 1
r_1.value = order.random()

c0, c1 = enc(g, order, pk_T, v.value, r_1.value)

enc_stmt1 = DLRep(c0, r_1*g) & DLRep(c1, v*g + r_1*pk_T)

#Range proof for three candidates (vote is either 0, 1 or 2)
range_stmt = RangeStmt(c1, g, pk_T, 0, 3, v, r_1)

#Second proof of encryption
lv.value = order.random() #this should maybe be something else? A list or something
r_2.value = order.random()

c2, c3 = enc(g, order, pk_vs, lv.value, r_2.value)

enc_stmt2 = DLRep(c2, r_2*g) & DLRep(c3, lv*g + r_2*pk_vs)

#Proof of re-encryption



#Proof
stmt = enc_stmt1 & range_stmt & enc_stmt2
nizk = stmt.prove({v: v.value, r_1: r_1.value, lv: lv.value, r_2: r_2.value})
v = stmt.verify(nizk)
print("Proof verified:", v)