#From ZKSK tutorial
# https://zksk.readthedocs.io/en/latest/usage.html#defining-a-simple-proof-statement

import zksk;
import petlib.bn as bn;
import petlib.ec as ec;

group = ec.EcGroup()

g0 = group.hash_to_point(b"g0")
g1 = group.hash_to_point(b"g1")

#Preparing the secrets
x0 = zksk.Secret()
x1 = zksk.Secret()

#First compute value of "left-hand side"
y = 4 * g0 + 42 * g1

#Create proof statement
stmt = zksk.DLRep(y, x0*g0 + x1*g1)

#commitment = 

prover = stmt.get_prover({x0: 4, x1: 42})
verifier = stmt.get_verifier()

commitment = (stmt, y)

challenge = verifier.send_challenge(commitment)
response = prover.compute_response(challenge)
assert verifier.verify(response)


