from zksk import Secret, DLRep, utils
from zksk.composition import OrProofStmt
from zksk.primitives.rangeproof import RangeStmt, RangeOnlyStmt
from zksk.primitives.dl_notequal import DLNotEqual
from zksk.utils.groups import make_generators
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc, re_enc

#Voter generates own sk og pk
group, g, order, pk_vs, sk_vs = keygen()


#Program generates other sks and pks, but voter only knows pks
sk_T = order.random() #Tallier
pk_T = sk_T*g

#Voter witnesses
sk = Secret()
r_v = Secret()
r_lv = Secret()
r_lvs = Secret()

#Generates previous three encryptions
c0_v, c1_v = enc(g, order, pk_T, 2, order.random())


lv = bn.Bn(211).random()
lvs = bn.Bn(211).random() #how do I make sure that m>1?
if lvs > lv:
    lvs = lv-1

c0_lv, c1_lv = enc(g, order, pk_vs, lv, order.random())

c0_lvs, c1_lvs = enc(g, order, pk_vs, lvs, order.random())

c0_i = 2*c0_lv
c1_i = 2*c1_lv

ct_i = (c0_i, c1_i)


#First proof of re-encryption, ct_v
r_v.value = order.random()

reEnc1 = re_enc(g, order, pk_T, (c0_v, c1_v), r_v.value) #PK_T or PK_VS here?

c0_v_Prime, c1_v_Prime = reEnc1

one = Secret(name="one", value=1)

reenc_stmt1 = DLRep(c0_v_Prime, one*c0_v + r_v*g) & DLRep(c1_v_Prime, one*c1_v + r_v*pk_T)

#Proof of Decryption
sk.value = sk_vs
c0 = c0_lv.pt_add(c0_lvs.pt_neg())  #c0_lv.mod_sub(c0_lvs, order) #c0_lv+(-c0_lvs) #c0_lv+(-1)*c0_lvs  #c0_lv-c0_lvs
c1 = c1_lv.pt_add(c1_lvs.pt_neg())  #c1_lv.mod_sub(c1_lvs, order) #c1_lv+(-c1_lvs) #c1_lv+(-1)*c1_lvs  #c1_lv-c1_lvs
ct = (c0, c1)

m_dec = dec(ct, sk.value)

one = Secret(name="one", value=1)
neg_x = Secret(name="neg_x", value = -sk_vs)

dec_stmt = DLRep(m_dec, one*c1 + neg_x*c0) 

#Proof of inequality to check that m >= 1

#enc = enc(g, order, pk_vs, m_dec, 0)

#x = Secret(value = m_dec)

#_, h = make_generators(2, group)

#r = Secret(value=0)

m = Secret(value=0)

print("c0:", c0, "type:", type(c0))
print("c1:", c1, "type:", type(c1))
print("lv:", lv, "type:", type(lv))
print("lvs:", lvs, "type:", type(lvs))
print("m_dec:", m_dec, "type:", type(m_dec))
print("c0_i:", c0_i, "type:", type(c0_i))
print("c1_i:", c1_i, "type:", type(c1_i))

for i in range(1,1000):
    if m_dec == i*g:
        """
        if i < 0:
            print("i before:",i)
            x1, _ = m_dec.get_affine()
            x2, _ = (i*g).get_affine()
            print("m_dec equal before:", x1 == x2)
            i = i % 211
            print("i after:",i)
            x1, _ = m_dec.get_affine()
            x2, _ = (i*g).get_affine()
            print("m_dec equal:", x1 == x2)
            """
        #if i < 0:
        #    i = -i
        m.value = i

print("m:",m.value)

#com = m*g + r*h

range_stmt = RangeOnlyStmt(1, 1000, m)

#range_stmt = RangeStmt(com, g, h, 1, 5, m, r)

#Second proof of re-encryption

r_lv.value = order.random()

reEnc2 = re_enc(g, order, pk_vs, ct_i, r_lv.value)

c0_lv_Prime, c1_lv_Prime = reEnc2

one = Secret(name="one", value=1)

reenc_stmt2 = DLRep(c0_lv_Prime, one*c0_i + r_lv*g) & DLRep(c1_lv_Prime, one*c1_i + r_lv*pk_vs)


#Third proof of re-encryption
r_lvs.value = order.random()

reEnc3 = re_enc(g, order, pk_vs, ct_i, r_lvs.value)

c0_lvs_Prime, c1_lvs_Prime = reEnc3

one = Secret(name="one", value=1)

reenc_stmt3 = DLRep(c0_lvs_Prime, one*c0_i + r_lvs*g) & DLRep(c1_lvs_Prime, one*c1_i + r_lvs*pk_vs)

#Proof
stmt = reenc_stmt1 & dec_stmt & range_stmt & reenc_stmt2 & reenc_stmt3
nizk = stmt.prove({sk: sk.value, r_v: r_v.value, r_lv: r_lv.value, r_lvs: r_lvs.value})
v = stmt.verify(nizk)
print("Proof verified:", v)