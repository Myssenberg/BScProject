"""Example of a simple proof of decryption construction
with the ZKSK library

This file contains a simple example of a proof of decryption built
with the ZKSK library.

To model a proof of decryption, first an encryption has to be made,
as one cannot decrypt something without first having an
encrypted ciphertext.
This is illustrated by a classic Alice and Bob example, where Alice
is the one encrypting a message for Bob to encrypt. 

This file requires that the environment you are running on have the 'ZKSK'
library installed.

This file does not take any arguments when running, but input values
can be tweaked in the file between runs to experiment.

The code in this file illustrates a successfully built
proof of decryption and running the file as is will print out True.
"""

from zksk import Secret, DLRep
from elGamal import keygen, dec, enc

#Generating group and Bob's key pair
g, order, pk, sk = keygen()

#Alice encrypts a message for Bob

#Note that the values are not saved as variables as they are not
#a part of the values that Bob knows when starting decryption
ct = enc(g, pk, 2, order.random())
c0, c1 = ct


#Bob's decryption

#Instatiating prover(Bob) witness with a value
#The value is added here already as it is used for the decryption
x = Secret(value=sk)

#Decrypting the message using the value of the prover witness
m_dec = dec(ct, x.value)

#As the DLRep only allows for expressions of type secret*EcPt a
#'dummy' Secret  with value 1 has to be instantiated to be multiplied
#to c1 to mimic the decryption process without altering the outcome.
one = Secret(name="one", value=1)

#As the expression of type secret*EcPt does not have a subtraction
#operation built in, c0 is negated here to mimic the decryption process
#without altering the outcome.
neg_c0 = (-1)*c0

#Building the proof of decryption statement
#Notice the two workarounds with "one" and "neg_c0" as described above
dec_stmt = DLRep(m_dec, one*c1 + x*neg_c0)

#Generating non-interactive proof
#Stating witness(es) for the relation to be proven
nizk = dec_stmt.prove({x: x.value})

#Verifying proof
v = dec_stmt.verify(nizk)
print("Proof verified: ", v)