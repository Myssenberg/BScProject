from zksk import Secret, DLRep, utils
from zksk.composition import OrProofStmt
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup
from elGamal import keygen, dec, enc, re_enc

#I know 'a' such that 'g^a mod p = b'

group, g, order, pk, sk = keygen()

x = Secret(value=sk)

y = sk * g

stmt = zksk.DLRep(y, x * g)

nizk = stmt.prove({x: x.value})
v = stmt.verify(nizk)

print("Proof verified:", v)