"""Example of a simple Proof of Knowledge construction with the ZKSK library

This file contains a simple example of a Proof of Knowledge built
with the ZKSK library.

This file requires that the environment you are running on have the 'ZKSK'
library installed.

This file does not take any arguments when running, but input values
can be tweaked in the file between runs to experiment.

The code in this file illustrates a successfully built Proof of Knowledge,
and running the file as is will print out True.
"""

from zksk import Secret, DLRep
from petlib.ec import EcGroup

#Generating group and generator
group = EcGroup()
g = group.generator()

#Tnstanciates a prover witness
x = Secret()

#Instatiating the public value
y = 5*g

#Building the proof statement
#'Saying' that the value of "y" should be the same as the value of
#"x*g", "x" being the secret knowledge.
stmt = DLRep(y, x*g)

#Generating non-interactive proof
#Stating witness(es) for the relation to be proven
#Takes care of the three steps of commitment, challenge and response
nizk = stmt.prove({x: 5}) 

#Verifying proof
v = stmt.verify(nizk)
print("Proof verified:", v)