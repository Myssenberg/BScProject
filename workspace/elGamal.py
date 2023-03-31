import random
from petlib.ec import EcGroup

def keygen(): #inspiration from https://github.com/gdanezis/petlib/blob/master/examples/AHEG.py
    group = EcGroup()
    g = group.generator()
    order = group.order()
    sk = order.random()
    pk = sk * g
    
    return (g, order, pk, sk)


def enc(g, order, pk, m):
    r = order.random()

    #Elliptic curve so g**m * pk**r becomes m*g + r*pk
    c0 = r*g
    c1 = m*g + r*pk

    return (c0, c1)

def dec(c, sk):
    c0, c1 = c
    #Should this be changed for ec as well?
    message = c1 + (c0*(-sk))

    return message/g


g, order, pk, sk = keygen()
e = enc(g, order, pk, 0)
m = dec(e, sk)
print(m)