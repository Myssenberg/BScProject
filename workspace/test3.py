from petlib.bn import Bn
from petlib.ec import EcGroup

from zksk.utils.groups import make_generators

group = EcGroup()

g1, g2 = make_generators(2, group)

print(g1)

print(g2)

v1 = group.order() * g1 == group.infinite()

v2 = group.order() *g2 == group.infinite ()

print("v1:", v1)
print("v2:", v2)