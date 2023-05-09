from petlib.ec import EcGroup

def keygen(): #inspiration from https://github.com/gdanezis/petlib/blob/master/examples/AHEG.py
    group = EcGroup()
    g = group.generator()
    order = group.order()
    sk = order.random()
    pk = sk * g
    
    return (g, order, pk, sk)


def enc(g, pk, m, r):
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



def re_enc(g, h, ct, r):
    c0, c1 = ct

    c0Prime = c0 + r*g
    c1Prime = c1 + r*h

    return (c0Prime, c1Prime)