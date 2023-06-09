"""Example of a simple proof of encryption construction
with the ZKSK library

This file contains a simple example of a proof of encryption built
with the ZKSK library.

This file requires that the environment you are running on have the 'ZKSK'
library installed.

This file does not take any arguments when running, but input values
can be tweaked in the file between runs to experiment.

The code in this file illustrates a successfully built
proof of encryption and running the file as is will print out True.
"""

from zksk import Secret, DLRep
from elGamal import keygen, enc

#Generating group and key pair
g, order, pk, sk = keygen()

#Instatiating prover witnesses with values
#Values are added here already as they are used for the encryption
m = Secret(value=1)
r = Secret(value=order.random())

#Encrypting the message using the prover witnesses
c0, c1 = enc(g, pk, m.value, r.value)

#Building the proof of encryption statement
#It is a conjoint proof, proving the values of c0 and c1 separately
enc_stmt = DLRep(c0, r*g) & DLRep(c1, m*g + r*pk)

#Generating non-interactive proof
#Stating witness(es) for the relation to be proven
nizk = enc_stmt.prove({m: m.value, r: r.value})

#Verifying proof
v = enc_stmt.verify(nizk)
print("Proof verified: ", v)