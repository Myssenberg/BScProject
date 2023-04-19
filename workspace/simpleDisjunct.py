from zksk import Secret, DLRep
from zksk.composition import OrProofStmt
import zksk
import petlib.bn as bn
import petlib.ec as ec
from petlib.ec import EcGroup

group = EcGroup()

g0 = group.generator()
#g1 = group.generator()

x0 = Secret(name="x0")
x1 = Secret(name="x1")

y0 = 3 * g0
y1 = 5 * g0

stmt = DLRep(y0, x0 * g0) | DLRep(y1, x1 * g0)
stmt.subproofs[1].set_simulated()

nizk = stmt.prove({x0: 3})
v = stmt.verify(nizk)
print(v)




"""
group = EcGroup()

g0 = group.hash_to_point(b"one")
g1 = group.hash_to_point(b"two")

x0 = Secret(value=3)
x1 = Secret(value=40)

y0 = x0.value * g0
y1 = x1.value * g1

stmt = DLRep(y0, x0 * g0) | DLRep(y1, x1 * g1)
stmt.subproofs[0].set_simulated()

prover = stmt.get_prover()
verifier = stmt.get_verifier()

commitment = prover.commit()
challenge = verifier.send_challenge(commitment)
response = prover.compute_response(challenge)
assert verifier.verify(response)
"""