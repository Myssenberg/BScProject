import zksk;
import petlib.bn as bn;
import petlib.ec as ec;
from petlib.ec import EcGroup

#I know 'a' such that 'g^a mod p = b'
"""
p = 7
g = 3
a = zksk.Secret(2)
r = zksk.Secret(4)

com = g**r

stmt = zksk.DLRep(com, g**x, )

"""

x = zksk.Secret(name="x")
g = EcGroup().generator()
y = 100 * g
stmt = zksk.DLRep(y, x * g)
nizk = stmt.prove({x: 100})
v = stmt.verify(nizk)

print(v)
print(nizk)
print(x.value)
print(g)

