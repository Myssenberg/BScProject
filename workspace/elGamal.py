import random
from petlib.ec import EcGroup

def keygen(): #inspiration from https://github.com/gdanezis/petlib/blob/master/examples/AHEG.py
    group = EcGroup()
    g = group.generator()
    order = group.order()
    sk = order.random()
    pk = sk * g
    
    return (group, g, order, pk, sk)


def enc(g, order, pk, m, r):
    
    #r = order.random() ... randomness generation moved to enc proof

    #Elliptic curve so g**m * pk**r becomes m*g + r*pk
    c0 = r*g
    c1 = m*g + r*pk

    return (c0, c1)

def dec(c, sk):
    c0, c1 = c
    print(c0)
    print(sk)

    message = (c1 + (-sk*c0))

    return message



def re_enc(g, order, h, ct, rPrime):
    c0, c1 = ct

    #rPrime = order.random()

    c0Prime = c0 + rPrime*g
    c1Prime = c1 + rPrime*h

    return (c0Prime, c1Prime)




group, g, order, pk, sk = keygen()
e = enc(g, order, pk, 1, order.random())
m = dec(e, sk)
print(m)
v = m == 1*g
print(v)

reenc = re_enc(g, order, pk, e, order.random())

print(reenc)