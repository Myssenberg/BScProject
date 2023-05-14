"""Example of a simple range proof construction with the ZKSK library

This file contains a simple example of a range proof built
with the ZKSK library.

This file requires that the environment you are running on have the 'ZKSK'
library installed.

This file does not take any arguments when running, but input values
can be tweaked in the file between runs to experiment.

The code in this file illustrates a successfully built
range proof and running the file as is will print out True.
"""

from zksk import Secret
from zksk.primitives.rangeproof import RangeOnlyStmt
from petlib import ec

#Generating group and generator
group = ec.EcGroup()
g = group.generator()

#Instatiating prover witnesses with values
#Values are added here already as the range proof fails if not given
x = Secret(value = 2)

#Stating the range
#The first number in range is inclusive and the last is exclusive,
#making the range here 3, with possible values in range: 0, 1, 2
#The minimum range allowed in this library construction is 3
lo = 0
hi = 3

#Building the range proof statement
#Checking that the witness is within the given range
stmt = RangeOnlyStmt(lo, hi, x)

#Generating non-interactive proof
#Stating witness(es) for the relation to be proven
nizk = stmt.prove({x: 2})

#Verifying proof
verify = stmt.verify(nizk)
print("Proof verified: ", verify)