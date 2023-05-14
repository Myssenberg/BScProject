"""Elliptic Curve ElGamal implementation

This file contains an Elliptic Curve ElGamal implementation,
containing group and key generation, and functions for encryption,
decryption and re-encryption.

The functions in this file are imported and used for the proof related
implementations in other files of this project.

This file requires that the environment you are running on have the 'petlib'
library installed, which comes with an installation of the 'ZKSK' library
needed for the other files in this project.

The file contains the following functions:
    - keygen: returns the group generator, order, and a key pair
    - enc: returns an EC elgamal encrypted ciphertext
    - dec: returns an EC elgamal decrypted message
    - re_enc: returns an EC elgamal re-encrypted ciphertext
"""

from petlib.ec import EcGroup

def keygen():
    """Generates an EC group, generator, order and key pair

    Args:
        no arguments
    
    Returns:
        g (EcPt): group generator
        order (Bn): group order
        pk (EcPt): public key
        sk (Bn): secret key
    """
    
    #Using the petlib library group operations to generate group
    #and group values
    group = EcGroup()
    g = group.generator()
    order = group.order()

    #Generating secret key at random from the EC group
    sk = order.random()
    pk = sk * g
    
    return (g, order, pk, sk)


def enc(g, pk, m, r):
    """Encryption of a message

    Args:
        g (EcPt): group generator
        pk (EcPt): public key of the receiver
        m (Bn) or (int): message to be encrypted
        r (Bn) : randomness
    
    Returns:
        (c0,c1) (EcPt, EcPt): ciphertext of encrypted message (c0, c1),
                              where c0 = r*g and c1 = m*g + r*pk
    """
    
    #Elliptic Curve so g**m * pk**r becomes m*g + r*pk
    c0 = r*g
    c1 = m*g + r*pk

    return (c0, c1)

def dec(ct, sk):
    """Decryption of a ciphertext

    Args:
        ct (EcPt, EcPt): ciphertext of encrypted message (c0, c1),
                        where c0 = r*g and c1 = m*g + r*pk
        sk (Bn): secret key / decryption key
    
    Returns:
        message (EcPt): decrypted message, m, on the form m*g
    """

    c0, c1 = ct

    message = (c1 + (-sk*c0))

    return message



def re_enc(g, pk, ct, r):
    """Re-Encryption of a ciphertext

    Args:
        g (EcPt): group generator
        pk (EcPt): public key of the receiver
        ct (EcPt, EcPt): ciphertext of encrypted message (c0, c1),
                         where c0 = r*g and c1 = m*g + r*pk
        r (Bn): randomness
    
    Returns:
        (c0Prime, c1Prime) (EcPt, EcPt): ciphertext (c0Prime, c1Prime)
                                         of re-encrypted ciphertext (c0, c1),
                                         where c0 = r*g and c1 = m*g + r*pk and,
                                         c0Prime = c0 + r*g and c1Prime = c1 + r*pk
    """
    
    c0, c1 = ct

    c0Prime = c0 + r*g
    c1Prime = c1 + r*pk

    return (c0Prime, c1Prime)