from zksk import Secret, DLRep
from zksk.composition import OrProofStmt
from zksk.primitives.rangeproof import RangeStmt, RangeOnlyStmt
from zksk.utils import make_generators
from petlib import ec
import zksk

"""
x = Secret(value=4)

lo = 0
hi = 3 #strictly x smaller than, so for two candidates it should be 2, because x can then be =0 or =1, but not =2

stmt = RangeOnlyStmt(lo, hi, x)

nizk = stmt.prove()

verify = stmt.verify(nizk)

print("Proof verified: ", verify)
"""

group = ec.EcGroup()


x = Secret(value=15)
randomizer = Secret(value=group.order().random())

g, h = make_generators(2, group)
lo = 7
hi = 15

com = x * g + randomizer * h

stmt = RangeStmt(com.eval(), g, h, lo, hi, x, randomizer)