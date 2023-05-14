"""Example of a simple proof of encryption w. range construction
with the ZKSK library

This file contains a simple example of a proof of encryption w. range built
with the ZKSK library.

This file requires that the environment you are running on have the 'ZKSK'
library installed.

This file does not take any arguments when running, but input values
can be tweaked in the file between runs to experiment.

The code in this file illustrates a successfully built
proof of encryption w. range and running the file as is
will print out True.
"""

from zksk import Secret, DLRep
from zksk.primitives.rangeproof import RangeStmt
from elGamal import keygen, enc

#Generating group and key pair
g, order, pk, sk = keygen()

#Instatiating prover witnesses with values
#Values are added here already as they are used for the encryption
m = Secret(value = 2)
r = Secret(value = order.random())

#Encrypting the message using the prover witnesses
c0, c1 = enc(g, pk, m.value, r.value)

#Building the proof of encryption statement
#It is a conjoint proof, proving the values of c0 and c1 separately
enc_stmt = DLRep(c0, r*g) & DLRep(c1, m*g + r*pk)

#Range proof with the same values from encryption
#Checking that the message encrypted is within the given range
#The first number in range is inclusive and the last is exclusive,
#making the range here 3, with possible values in range: 0, 1, 2
#The minimum range allowed in this library construction is 3
range_stmt = RangeStmt(c1, g, pk, 0, 3, m, r)

#Building the encryption w. range statement
#a conjoint statement of the proof of encryption and range proof
stmt = enc_stmt & range_stmt

#Generating non-interactive proof
#Stating witness(es) for the relation to be proven
nizk = stmt.prove({m: m.value, r: r.value})

#Verifying proof
v = stmt.verify(nizk)
print("Proof verified: ", v)