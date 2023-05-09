from zksk import Secret, DLRep
from zksk.primitives.rangeproof import RangeStmt, RangeOnlyStmt
import zksk
import petlib.bn as bn
from elGamal import keygen, dec, enc, re_enc
import time

#Voter generates own sk og pk
g, order, pk_id, sk_id = keygen()


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

start = time.process_time_ns()
R1_c0, R1_c1 = enc(g, pk_T, R1_v.value, R1_r_v.value)
time_R1_enc1 = time.process_time_ns() - start

enc_stmt1 = DLRep(R1_c0, R1_r_v*g) & DLRep(R1_c1, R1_v*g + R1_r_v*pk_T)

#Range proof for three candidates (vote is either 0, 1 or 2)
R1_range_stmt = RangeStmt(R1_c1, g, pk_T, 0, 16, R1_v, R1_r_v)

#Second proof of encryption
R1_lv.value = order.random()
R1_r_lv.value = order.random()

start = time.process_time_ns()
c2, c3 = enc(g, pk_vs, R1_lv.value, R1_r_lv.value)
time_R1_enc2 = time.process_time_ns() - start

enc_stmt2 = DLRep(c2, R1_r_lv*g) & DLRep(c3, R1_lv*g + R1_r_lv*pk_vs)

#Proof of re-encryption
c4, c5 = enc(g, pk_vs, 0, order.random()) #don't need to know these values for later

R1_r_lvs.value = order.random()

start = time.process_time_ns()
reEnc = re_enc(g, pk_vs, (c4, g+c5), R1_r_lvs.value)
time_R1_reenc = time.process_time_ns() - start

c4Prime, c5Prime = reEnc

one = Secret(name="one", value=1)

reenc_stmt = DLRep(c4Prime, one*c4 + R1_r_lvs*g) & DLRep(c5Prime, one*(c5+g) + R1_r_lvs*pk_vs)


#Proof of knowledge
R1_sk.value = sk_id

y = R1_sk.value * g

know_stmt = zksk.DLRep(y, R1_sk * g)

#Relation 1 statement
relation1 = enc_stmt1 & R1_range_stmt & enc_stmt2 & reenc_stmt & know_stmt



#RELATION 2
#Voter witnesses
R2_sk = Secret()
R2_r_v = Secret()
R2_r_lv = Secret()
R2_r_lvs = Secret()

#Generates previous three encryptions
R2_c0_v, R2_c1_v = enc(g, pk_T, 1, order.random())


R2_lv = R2_lvs = order.random() #lv and lvs instatiated as the same here to make the proof run

R2_c0_lv, R2_c1_lv = enc(g, pk_vs, R2_lv, order.random())

R2_c0_lvs, R2_c1_lvs = enc(g, pk_vs, R2_lvs, order.random())

R2_c0_i = 2*R2_c0_lvs
R2_c1_i = 2*R2_c1_lvs

R2_ct_i = (R2_c0_i, R2_c1_i)



#First proof of re-encryption, ct_v
R2_r_v.value = order.random()

start = time.process_time_ns()
R2_reEnc1 = re_enc(g, pk_T, (R2_c0_v, R2_c1_v), R2_r_v.value)
time_R2_reenc1 = time.process_time_ns() - start

R2_c0_v_Prime, R2_c1_v_Prime = R2_reEnc1

one = Secret(name="one", value=1)

R2_reenc_stmt1 = DLRep(R2_c0_v_Prime, one*R2_c0_v + R2_r_v*g) & DLRep(R2_c1_v_Prime, one*R2_c1_v + R2_r_v*pk_T)

#Proof of Decryption
R2_sk.value = sk_vs
R2_c0 = R2_c0_lv-R2_c0_lvs
R2_c1 = R2_c1_lv-R2_c1_lvs
R2_ct = (R2_c0, R2_c1)

start = time.process_time_ns()
R2_m_dec = dec(R2_ct, R2_sk.value)
time_R2_dec = time.process_time_ns() - start

one = Secret(name="one", value=1)
R2_neg_c0 = (-1)*R2_c0

R2_dec_stmt = DLRep(0*g, one*R2_c1 + R2_sk*R2_neg_c0)

#Second proof of re-encryption

R2_r_lv.value = order.random()

start = time.process_time_ns()
R2_reEnc2 = re_enc(g, pk_vs, R2_ct_i, R2_r_lv.value)
time_R2_reenc2 = time.process_time_ns() - start

R2_c0_lv_Prime, R2_c1_lv_Prime = R2_reEnc2

one = Secret(name="one", value=1)

R2_reenc_stmt2 = DLRep(R2_c0_lv_Prime, one*R2_c0_i + R2_r_lv*g) & DLRep(R2_c1_lv_Prime, one*R2_c1_i + R2_r_lv*pk_vs)


#Third proof of re-encryption
R2_r_lvs.value = order.random()

start = time.process_time_ns()
R2_reEnc3 = re_enc(g, pk_vs, R2_ct_i, R2_r_lvs.value)
time_R2_reenc3 = time.process_time_ns() - start

R2_c0_lvs_Prime, R2_c1_lvs_Prime = R2_reEnc3

one = Secret(name="one", value=1)

R2_reenc_stmt3 = DLRep(R2_c0_lvs_Prime, one*R2_c0_i + R2_r_lvs*g) & DLRep(R2_c1_lvs_Prime, one*R2_c1_i + R2_r_lvs*pk_vs)

#Relation 2 statement
relation2 = R2_reenc_stmt1 & R2_dec_stmt & R2_reenc_stmt2 & R2_reenc_stmt3


#RELATION 3
#Voter witnesses
R3_sk = Secret()
R3_r_v = Secret()
R3_r_lv = Secret()
R3_r_lvs = Secret()

#Generates previous three encryptions
R3_c0_v, R3_c1_v = enc(g, pk_T, 2, order.random())


lv = bn.Bn(211).random()
lvs = bn.Bn(211).random()
if lvs > lv:
    lvs = lv-1

R3_c0_lv, R3_c1_lv = enc(g, pk_vs, lv, order.random())

R3_c0_lvs, R3_c1_lvs = enc(g, pk_vs, lvs, order.random())

R3_c0_i = 2*R3_c0_lvs
R3_c1_i = 2*R3_c1_lvs

R3_ct_i = (R3_c0_i, R3_c1_i)


#First proof of re-encryption
R3_r_v.value = order.random()

start = time.process_time_ns()
R3_reEnc1 = re_enc(g, pk_T, (R3_c0_v, R3_c1_v), R3_r_v.value)
time_R3_reenc1 = time.process_time_ns() - start

R3_c0_v_Prime, R3_c1_v_Prime = R3_reEnc1

one = Secret(name="one", value=1)

R3_reenc_stmt1 = DLRep(R3_c0_v_Prime, one*R3_c0_v + R3_r_v*g) & DLRep(R3_c1_v_Prime, one*R3_c1_v + R3_r_v*pk_T)

#Proof of Decryption
R3_sk.value = sk_vs
R3_c0 = R3_c0_lv - R3_c0_lvs
R3_c1 = R3_c1_lv - R3_c1_lvs
R3_ct = (R3_c0, R3_c1)

start = time.process_time_ns()
R3_m_dec = dec(R3_ct, R3_sk.value)
time_R3_dec = time.process_time_ns() - start

one = Secret(name="one", value=1)
R3_neg_c0 = (-1)*R3_c0

R3_dec_stmt = DLRep(R3_m_dec, one*R3_c1 + R3_sk*R3_neg_c0) 

#Proof of inequality to check that m >= 1

m = Secret(value=0)

for i in range(1,1000):
    if R3_m_dec == i*g:
        m.value = i

R3_range_stmt = RangeOnlyStmt(1, 1000, m)

#Second proof of re-encryption

R3_r_lv.value = order.random()

start = time.process_time_ns()
R3_reEnc2 = re_enc(g, pk_vs, R3_ct_i, R3_r_lv.value)
time_R3_reenc2 = time.process_time_ns() - start

R3_c0_lv_Prime, R3_c1_lv_Prime = R3_reEnc2

one = Secret(name="one", value=1)

R3_reenc_stmt2 = DLRep(R3_c0_lv_Prime, one*R3_c0_i + R3_r_lv*g) & DLRep(R3_c1_lv_Prime, one*R3_c1_i + R3_r_lv*pk_vs)


#Third proof of re-encryption
R3_r_lvs.value = order.random()

start = time.process_time_ns()
R3_reEnc3 = re_enc(g, pk_vs, R3_ct_i, R3_r_lvs.value)
time_R3_reenc3 = time.process_time_ns() - start

R3_c0_lvs_Prime, R3_c1_lvs_Prime = R3_reEnc3

one = Secret(name="one", value=1)

R3_reenc_stmt3 = DLRep(R3_c0_lvs_Prime, one*R3_c0_i + R3_r_lvs*g) & DLRep(R3_c1_lvs_Prime, one*R3_c1_i + R3_r_lvs*pk_vs)

#Proof
relation3 = R3_reenc_stmt1 & R3_dec_stmt & R3_range_stmt & R3_reenc_stmt2 & R3_reenc_stmt3



#PROOFS


"""
#Relation 1 proof
stmt = relation1 | relation2 | relation3
stmt.subproofs[1].set_simulated()
stmt.subproofs[2].set_simulated()

start = time.process_time_ns()
nizk = stmt.prove({R1_v: R1_v.value, R1_r_v: R1_r_v.value, R1_lv: R1_lv.value, R1_r_lv: R1_r_lv.value, R1_r_lvs: R1_r_lvs.value, R1_sk: R1_sk.value})
time_R1_prove = time.process_time_ns() - start

start = time.process_time_ns()
v = stmt.verify(nizk)
time_R1_verify = time.process_time_ns() - start

print("Proof verified:", v)

ballot_generation_time = time_R1_enc1 + time_R1_enc2 + time_R1_reenc + time_R1_prove
print("Ballot generation time:", ballot_generation_time)
print("Ballot verification time:", time_R1_verify)

"""

"""
#Relation 2 proof
stmt = relation1 | relation2 | relation3
stmt.subproofs[0].set_simulated()
stmt.subproofs[2].set_simulated()

start = time.process_time_ns()
nizk = stmt.prove({R2_r_v: R2_r_v.value, R2_r_lv: R2_r_lv.value, R2_r_lvs: R2_r_lvs.value, R2_sk: R2_sk.value})
time_R2_prove = time.process_time_ns()-start

start = time.process_time_ns()
v = stmt.verify(nizk)
time_R2_verify = time.process_time_ns()-start

print("Proof verified:", v)

R2_ballot_randomization_time = time_R2_reenc1 + time_R2_dec + time_R2_reenc2 + time_R2_reenc3 + time_R2_prove
print("Ballot randomization time (relation 2):", R2_ballot_randomization_time)
print("Ballot verification time:", time_R2_verify)


"""

#Relation 3 proof
stmt = relation1 | relation2 | relation3
stmt.subproofs[0].set_simulated()
stmt.subproofs[1].set_simulated()

start = time.process_time_ns()
nizk = stmt.prove({R3_sk: R3_sk.value, R3_r_v: R3_r_v.value, R3_r_lv: R3_r_lv.value, R3_r_lvs: R3_r_lvs.value})
time_R3_prove = time.process_time_ns()-start

start = time.process_time_ns()
v = stmt.verify(nizk)
time_R3_verify = time.process_time_ns()-start

print("Proof verified:", v)

R3_ballot_randomization_time = time_R3_reenc1 + time_R3_dec + time_R3_reenc2 + time_R3_reenc3 + time_R3_prove
print("Ballot randomization time (relation 3):", R3_ballot_randomization_time)
print("Ballot verification time:", time_R3_verify)


"""
#Example proof with all witnesses
stmt = relation1 | relation2 | relation3
stmt.subproofs[1].set_simulated()
stmt.subproofs[2].set_simulated()

start = time.process_time_ns()
nizk = stmt.prove({R1_v: R1_v.value, R1_r_v: R1_r_v.value, R1_lv: R1_lv.value, R1_r_lv: R1_r_lv.value, R1_r_lvs: R1_r_lvs.value, R1_sk: R1_sk.value,
                   R2_r_v: 0, R2_r_lv: 0, R2_r_lvs: 0, R2_sk: 0,
                   R3_r_v: 0, R3_r_lv: 0, R3_r_lvs: 0, R3_sk: 0})
time_R1_prove = time.process_time_ns() - start

start = time.process_time_ns()
v = stmt.verify(nizk)
time_R1_verify = time.process_time_ns() - start

print("Proof verified:", v)

ballot_generation_time = time_R1_enc1 + time_R1_enc2 + time_R1_reenc + time_R1_prove
print("Ballot generation time:", ballot_generation_time)
print("Ballot verification time:", time_R1_verify)
"""