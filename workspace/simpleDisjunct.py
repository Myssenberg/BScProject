"""Example of a simple disjoint proof construction with the ZKSK library

This file contains a simple example of a disjoint proof built
with the ZKSK library.

This file requires that the environment you are running on have the 'ZKSK'
library installed.

This file does not take any arguments when running, but input values
can be tweaked in the file between runs to experiment.

The code in this file illustrates a successfully built disjoint ZKP,
and running the file as is will print out True.
"""

from zksk import Secret, DLRep
from petlib.ec import EcGroup

#Generating group and generator
group = EcGroup()
g = group.generator()

#Instantiating the two Prover witnesses
x0 = Secret()
x1 = Secret()

#Instatiating public values
y0 = 3 * g
y1 = 5 * g

#Building a disjoint statement, of two separate and individual ZKPs
stmt = DLRep(y0, x0 * g) | DLRep(y1, x1 * g)

#Stating which proof should be simulated from the statement above
#Think of the disjoint statement as an array of subproofs
#in such an array, the second statement would be on index 1, 
#making the proof simulated in this example the second proof.
stmt.subproofs[1].set_simulated()

#Generating non-interactive proof
#Stating witness(es) for the relation to be proven
nizk = stmt.prove({x0: 3})

#Verifying proof
v = stmt.verify(nizk)
print("Proof verified: ", v)