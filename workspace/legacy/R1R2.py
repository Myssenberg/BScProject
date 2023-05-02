from zksk import Secret, DLRep, utils
from zksk.composition import OrProofStmt
from zksk.primitives.rangeproof import RangeStmt
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc, re_enc
import time

#Voter generates own sk og pk
group, g, order, pk_id, sk_id = keygen()


#Program generates other sks and pks, but voter only knows pks
sk_T = order.random() #Tallier
pk_T = sk_T*g

sk_vs = order.random() #Voting server
pk_vs = sk_vs*g


#RELATION 1
#Voter witnesses
R1_sk = Secret()

R1_v = Secret()
R1_lv = Secret()

R1_r_v = Secret()
R1_r_lv = Secret()
R1_r_lvs = Secret()

#First proof of encryption
R1_v.value = 1
R1_r_v.value = order.random()

c0, c1 = enc(g, order, pk_T, R1_v.value, R1_r_v.value)

enc_stmt1 = DLRep(c0, R1_r_v*g) & DLRep(c1, R1_v*g + R1_r_v*pk_T)

#Range proof for three candidates (vote is either 0, 1 or 2)
range_stmt = RangeStmt(c1, g, pk_T, 0, 3, R1_v, R1_r_v)

#Second proof of encryption
R1_lv.value = order.random() #this should maybe be something else? A list or something
R1_r_lv.value = order.random()

c2, c3 = enc(g, order, pk_vs, R1_lv.value, R1_r_lv.value)

enc_stmt2 = DLRep(c2, R1_r_lv*g) & DLRep(c3, R1_lv*g + R1_r_lv*pk_vs)

#Proof of re-encryption
c4, c5 = enc(g, order, pk_vs, 0, order.random()) #don't need to know these values for later

R1_r_lvs.value = order.random()

reEnc = re_enc(g, order, pk_vs, (c4, g+c5), R1_r_lvs.value)

c4Prime, c5Prime = reEnc

one = Secret(name="one", value=1)

reenc_stmt = DLRep(c4Prime, one*c4 + R1_r_lvs*g) & DLRep(c5Prime, one*(c5+g) + R1_r_lvs*pk_vs)


#Proof of knowledge
R1_sk.value = sk_id

y = R1_sk.value * g

know_stmt = zksk.DLRep(y, R1_sk * g)

#Relation 1 statement
relation1 = enc_stmt1 & range_stmt & enc_stmt2 & reenc_stmt & know_stmt



#RELATION 2
#Voter witnesses
R2_sk = Secret()
R2_r_v = Secret()
R2_r_lv = Secret()
R2_r_lvs = Secret()

#Generates previous three encryptions
c0_v, c1_v = enc(g, order, pk_T, 1, order.random())


R2_lv = R2_lvs = order.random() #lv and lvs instatiated as the same here to make the proof run

c0_lv, c1_lv = enc(g, order, pk_vs, R2_lv, order.random())

c0_lvs, c1_lvs = enc(g, order, pk_vs, R2_lvs, order.random())

c0_i = 2*c0_lv
c1_i = 2*c1_lv

ct_i = (c0_i, c1_i)



#First proof of re-encryption, ct_v
R2_r_v.value = order.random()

reEnc1 = re_enc(g, order, pk_T, (c0_v, c1_v), R2_r_v.value)

c0_v_Prime, c1_v_Prime = reEnc1

one = Secret(name="one", value=1)

reenc_stmt1 = DLRep(c0_v_Prime, one*c0_v + R2_r_v*g) & DLRep(c1_v_Prime, one*c1_v + R2_r_v*pk_T)

#Proof of Decryption
R2_sk.value = sk_vs
c0 = c0_lv-c0_lvs
c1 = c1_lv-c1_lvs
ct = (c0, c1)

m_dec = dec(ct, R2_sk.value)

one = Secret(name="one", value=1)
neg_c0 = (-1)*c0

dec_stmt = DLRep(0*g, one*c1 + R2_sk*neg_c0)

#Second proof of re-encryption

R2_r_lv.value = order.random()

reEnc2 = re_enc(g, order, pk_vs, ct_i, R2_r_lv.value)

c0_lv_Prime, c1_lv_Prime = reEnc2

one = Secret(name="one", value=1)

reenc_stmt2 = DLRep(c0_lv_Prime, one*c0_i + R2_r_lv*g) & DLRep(c1_lv_Prime, one*c1_i + R2_r_lv*pk_vs)


#Third proof of re-encryption
R2_r_lvs.value = order.random()

reEnc3 = re_enc(g, order, pk_vs, ct_i, R2_r_lvs.value)

c0_lvs_Prime, c1_lvs_Prime = reEnc3

one = Secret(name="one", value=1)

reenc_stmt3 = DLRep(c0_lvs_Prime, one*c0_i + R2_r_lvs*g) & DLRep(c1_lvs_Prime, one*c1_i + R2_r_lvs*pk_vs)

#Relation 2 statement
relation2 = reenc_stmt1 & dec_stmt & reenc_stmt2 & reenc_stmt3



#PROOFS

"""
#Relation 1 proof
stmt = relation1 | relation2
stmt.subproofs[1].set_simulated()

nizk = stmt.prove({R1_v: R1_v.value, R1_r_v: R1_r_v.value, R1_lv: R1_lv.value, R1_r_lv: R1_r_lv.value, R1_r_lvs: R1_r_lvs.value, R1_sk: R1_sk.value,
                   R2_r_v: 0, R2_r_lv: 0, R2_r_lvs: 0, R2_sk: 0})

R1_v = stmt.verify(nizk)
print("Proof verified:", R1_v)

"""

#Relation 2 proof
stmt = relation1 | relation2
stmt.subproofs[0].set_simulated()
start = time.process_time()
nizk = stmt.prove({R1_v: 0, R1_r_v: 0, R1_lv: 0, R1_r_lv: 0, R1_r_lvs: 0, R1_sk: 0,
                   R2_r_v: R2_r_v.value, R2_r_lv: R2_r_lv.value, R2_r_lvs: R2_r_lvs.value, R2_sk: R2_sk.value})
print("Generate proof time:", time.process_time()-start)

start = time.process_time_ns()
v = stmt.verify(nizk)
print("Verify proof time:", time.process_time_ns()-start)
print("Proof verified:", v)
