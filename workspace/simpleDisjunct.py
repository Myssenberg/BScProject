from zksk import Secret, DLRep
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup

g = EcGroup().generator()
print(g)
x0 = Secret(value = 20)
x1 = Secret()

y0 = x0 * g
y1 = x1 * g

stmt0 = DLRep(y0, x0 * g)
stmt1 = DLRep(y1, x1 * g)
stmt1.set_simulated()

stmt = zksk.composition.OrProofStmt(stmt0, stmt1)

nizk = stmt.prove()

v = nizk.verify()

print(v)