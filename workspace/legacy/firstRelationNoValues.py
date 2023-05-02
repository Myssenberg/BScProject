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
v_value = 1
r_1_value = order.random()

c0, c1 = enc(g, order, pk_T, v_value, r_1_value)

enc_stmt1 = DLRep(c0, r_1*g) & DLRep(c1, v*g + r_1*pk_T)

#Range proof for three candidates (vote is either 0, 1 or 2)
v.value = v_value
r_1.value = r_1_value
range_stmt = RangeStmt(c1, g, pk_T, 0, 3, v, r_1)

#Second proof of encryption
lv_value = order.random() #this should maybe be something else? A list or something
r_2_value = order.random()

c2, c3 = enc(g, order, pk_vs, lv_value, r_2_value)

enc_stmt2 = DLRep(c2, r_2*g) & DLRep(c3, lv*g + r_2*pk_vs)

#Proof of re-encryption
c4, c5 = enc(g, order, pk_vs, 0, order.random()) #don't need to know these values for later

r_3.value = order.random()

reEnc = re_enc(g, order, pk_vs, (c4, g+c5), r_3.value)

c4Prime, c5Prime = reEnc

one = Secret(name="one", value=1)

reenc_stmt = DLRep(c4Prime, one*c4 + r_3*g) & DLRep(c5Prime, one*(c5+g) + r_3*pk_vs)


#Proof of knowledge
sk.value = sk_id

y = sk.value * g

know_stmt = zksk.DLRep(y, sk * g)

#Proof
stmt = enc_stmt1 & range_stmt & enc_stmt2 & reenc_stmt & know_stmt
nizk = stmt.prove({v: v_value, r_1: r_1_value, lv: lv_value, r_2: r_2_value, r_3: r_3.value, sk: sk.value})
v = stmt.verify(nizk)
print("Proof verified:", v)