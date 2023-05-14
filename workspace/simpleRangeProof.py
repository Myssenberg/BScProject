from zksk import Secret, DLRep
from zksk.composition import OrProofStmt
from zksk.primitives.rangeproof import RangeStmt, RangeOnlyStmt
from zksk.utils import make_generators
from petlib import ec
import zksk


group = ec.EcGroup()
g = group.generator()

x = Secret(value=2)

lo = 1
hi = 10 #strictly x smaller than, so for two candidates it should be 2, because x can then be =0 or =1, but not =2

stmt = RangeOnlyStmt(lo, hi, x)

nizk = stmt.prove()

verify = stmt.verify(nizk)

print("Proof verified: ", verify)