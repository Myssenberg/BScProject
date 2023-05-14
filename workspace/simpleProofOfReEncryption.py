"""Example of a simple proof of re-encryption construction
with the ZKSK library

This file contains a simple example of a proof of re-encryption built
with the ZKSK library.

To model a proof of re-encryption, first an encryption has to be made,
as one cannot re-encrypt something without first having an
encrypted ciphertext.
This is illustrated by a classic Alice and Bob example, where Alice
is the one encrypting a message for Bob to re-encrypt. 

This file requires that the environment you are running on have the 'ZKSK'
library installed.

This file does not take any arguments when running, but input values
can be tweaked in the file between runs to experiment.

The code in this file illustrates a successfully built
proof of re-encryption and running the file as is will print out True.
"""

from zksk import Secret, DLRep
from elGamal import keygen, enc, re_enc

#Generating group and Bob's key pair
g, order, pk, sk = keygen()

#Alice encrypts a message for Bob

#Note that the values are not saved as variables as they are not
#a part of the values that Bob knows when starting re-encryption
ct = enc(g, pk, 2, order.random())
c0, c1 = ct

#Bob's re-encryption

#Instatiating prover(Bob) witness with a value
#The value is added here already as it is used for the re-encryption
rPrime = Secret(value=order.random())

#Re-encrypting the ciphertext using the value of the prover witness
reEnc = re_enc(g, pk, ct, rPrime.value)
c0Prime, c1Prime = reEnc

#As the DLRep only allows for expressions of type secret*EcPt a
#'dummy' Secret  with value 1 has to be instantiated to be multiplied
#to c0 and c1 to mimic the re-encryption process without altering the outcome.
one = Secret(name="one", value=1)

#Building the proof of re-encryption statement
#It is a conjoint proof, proving the values of
#c0Prime and c1Prime separately
#Notice the workaround with "one" as described above
reenc_stmt = DLRep(c0Prime, one*c0 + rPrime*g) & DLRep(c1Prime, one*c1 + rPrime*pk)

#Generating non-interactive proof
#Stating witness(es) for the relation to be proven
nizk = reenc_stmt.prove({rPrime: rPrime.value})

#Verifying proof
v = reenc_stmt.verify(nizk)
print("Proof verified: ", v)
