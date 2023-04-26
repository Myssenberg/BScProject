from zksk import Secret, DLRep
from zksk.composition import OrProofStmt
from zksk.primitives.rangeproof import RangeStmt, RangeOnlyStmt
from zksk.utils import make_generators
from petlib import ec
import zksk

"""
group = ec.EcGroup()
g = group.generator()

x = Secret(value=2*g)

lo = 1
hi = 1000000 #strictly x smaller than, so for two candidates it should be 2, because x can then be =0 or =1, but not =2

stmt = RangeOnlyStmt(lo, hi, x)

nizk = stmt.prove()

verify = stmt.verify(nizk)

print("Proof verified: ", verify)

"""
group = ec.EcGroup()


x = Secret(value= 13)
randomizer = Secret(value = group.order().random())

g, h = make_generators(2, group)
lo = 7
hi = 15

com = 13 * g + randomizer * h

stmt = RangeStmt(com, g, h, lo, hi, x, randomizer)

nizk = stmt.prove({x: 13, randomizer: randomizer.value})

verify = stmt.verify(nizk)

print("Proof verified:", verify)