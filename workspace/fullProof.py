"""Full proof for ballot verifiability from the Giustolisi et.al. paper

This file contains the full proof, consisting of all three relations
(R1, R2, R3) built in each of their own functions, as well as proof generation
for all three, and finally a verification function and a proof function to
execute the proof in full.

All three relations are built with sub-proofs, the construction of which
are documented in the other files in this folder. The same is true for the
implementation of elGamal used in this file.

This file does not take any arguments when running, but input values
can be tweaked in the file between runs.

This file requires that the environment you are running on have the 'ZKSK'
library installed.

The file contains the following functions:
    - ballotGeneration: returns the full conjoint statement for R1
                        and the witnesses
    - ballotRandomization2: returns the full conjoint statement for R2
                        and the witnesses
    - ballotRandomization3: returns the full conjoint statement for R3
                        and the witnesses
    - proofRelation1: returns the generated proof, when proving R1
    - proofRelation2: returns the generated proof, when proving R2
    - proofRelation3: returns the generated proof, when proving R3
    - verification: returns a boolean statement, determining whether
                    the proof was True or False
    - proof: returns the running time for individual parts of the proof
             and prints whether the proof was verified or not


At the end of the file some examples of how the time is measured are left in.
They are commented out, and are only for documentation purposes in
relation to the report and analysis.
"""

from zksk import Secret, DLRep
from zksk.primitives.rangeproof import RangeStmt, RangeOnlyStmt
import zksk
import petlib.bn as bn
from elGamal import keygen, dec, enc, re_enc
import time

#Generation of public params and voting server kay pair
g, order, pk_vs, sk_vs = keygen()

#Generation of Tallier key pair
sk_T = order.random()
pk_T = sk_T*g


def ballotGeneration(g, order, sk_id, pk_T, pk_vs):
    """Constructs all sub-proofs and witnesses for R1

    The order of sub-proofs in this relation is:
        - Proof of Encryption w. range (1)
        - Proof of Encryption (2)
        - Proof of Re-Encryption
        - Proof of Knowledge

    Args:
        g (EcPt): generator of the EC group
        order (Bn): order of the EC group
        sk_id (Bn): secret key of the Voter
        pk_T (EcPt): public key of the Tallier
        pk_vs(EcPt): public key of the Voting Server
    
    Returns:
        stmt (AndProofStmt): the conjoint proof of R1 sub-proofs
        R1_v (Secret): Prover witness, vote
        R1_r_v (Secret): Prover witness, randomness
        R1_lv (Secret): Prover witness, voter list
        R1_r_lv (Secret): Prover witness, randomness
        R1_r_lvs (Secret): Prover witness, randomness
        R1_sk (Secret): Prover witness, voter secret key
    """

    #PROVER WITNESSES
    R1_sk = Secret()

    R1_v = Secret()
    R1_lv = Secret()

    R1_r_v = Secret()
    R1_r_lv = Secret()
    R1_r_lvs = Secret()

    #FIRST PROOF OF ENCRYPTION
    #w. vote (R1_v) value 1
    R1_v.value = 1
    R1_r_v.value = order.random()

    R1_c0, R1_c1 = enc(g, pk_T, R1_v.value, R1_r_v.value)

    enc_stmt1 = DLRep(R1_c0, R1_r_v*g) & DLRep(R1_c1, R1_v*g + R1_r_v*pk_T)

    #RANGE PROOF. Candidates(range) can be adjusted.
    #Run with (0,4), (0,16) and (0,100) for 4, 16 and 100 candidates respectively
    R1_range_stmt = RangeStmt(R1_c1, g, pk_T, 0, 4, R1_v, R1_r_v)

    #SECOND PROOF OF DECRYPTION
    #w. voter list (R1_lv) value simulated by randomly chosen value
    R1_lv.value = order.random()
    R1_r_lv.value = order.random()

    c2, c3 = enc(g, pk_vs, R1_lv.value, R1_r_lv.value)

    enc_stmt2 = DLRep(c2, R1_r_lv*g) & DLRep(c3, R1_lv*g + R1_r_lv*pk_vs)

    #PROOF OF RE-ENCRYPTION
    c4, c5 = enc(g, pk_vs, 0, order.random())

    R1_r_lvs.value = order.random()

    #As in the paper, the generator is added onto the second value
    #in the ciphertext pair
    reEnc = re_enc(g, pk_vs, (c4, g+c5), R1_r_lvs.value)

    c4Prime, c5Prime = reEnc

    one = Secret(name="one", value=1)

    reenc_stmt = DLRep(c4Prime, one*c4 + R1_r_lvs*g) & DLRep(c5Prime, one*(c5+g) + R1_r_lvs*pk_vs)


    #PROOF OF KNOWLEDGE
    R1_sk.value = sk_id

    y = R1_sk.value * g

    know_stmt = zksk.DLRep(y, R1_sk * g)

    #RELATION 1 STATEMENT
    #Conjoining all sub-proofs.
    stmt = enc_stmt1 & R1_range_stmt & enc_stmt2 & reenc_stmt & know_stmt


    return stmt, R1_v, R1_r_v, R1_lv, R1_r_lv, R1_r_lvs, R1_sk

def ballotRandomization2(g, order, sk_vs, pk_T, pk_vs):
    """Constructs all sub-proofs and witnesses for R2

    The order of sub-proofs in this relation is:
        - Proof of Re-Encryption (1)
        - Proof of Decryption
        - Proof of Re-Encryption (2)
        - Proof of Re-Encryption (3)
    
    All stand-in encryptions for 'previous' encryption
    are done before constructing the sub-proofs.

    Args:
        g (EcPt): generator of the EC group
        order (Bn): order of the EC group
        sk_vs (Bn): secret key of the Voting Server
        pk_T (EcPt): public key of the Tallier
        pk_vs(EcPt): public key of the Voting Server
    
    Returns:
        stmt (AndProofStmt): the conjoint proof of R2 sub-proofs
        R2_r_v (Secret): Prover witness, randomness
        R2_r_lv (Secret): Prover witness, randomness
        R2_r_lvs (Secret): Prover witness, randomness
        R2_sk (Secret): Prover witness, Voting Server secret key
    """

    #PROVER WITNESSES
    R2_sk = Secret()
    R2_r_v = Secret()
    R2_r_lv = Secret()
    R2_r_lvs = Secret()

    #STAND-IN ENCRYPTIONS
    #Generates previous three encryptions as stated in the paper
    R2_c0_v, R2_c1_v = enc(g, pk_T, 1, order.random())

    #Voter list (lv) and Voting Server list (lvs) instatiated as
    #the same value here to accommodate the R2 scenario of a valid vote
    R2_lv = R2_lvs = order.random()

    R2_c0_lv, R2_c1_lv = enc(g, pk_vs, R2_lv, order.random())

    R2_c0_lvs, R2_c1_lvs = enc(g, pk_vs, R2_lvs, order.random())

    #New ciphertext made from encryption of a previous lvs as described
    #in the paper
    R2_c0_i = 2*R2_c0_lvs
    R2_c1_i = 2*R2_c1_lvs

    R2_ct_i = (R2_c0_i, R2_c1_i)

    #FIRST PROOF OF RE-ENCRYPTION
    R2_r_v.value = order.random()

    R2_reEnc1 = re_enc(g, pk_T, (R2_c0_v, R2_c1_v), R2_r_v.value)

    R2_c0_v_Prime, R2_c1_v_Prime = R2_reEnc1

    one = Secret(name="one", value=1)

    R2_reenc_stmt1 = DLRep(R2_c0_v_Prime, one*R2_c0_v + R2_r_v*g) & DLRep(R2_c1_v_Prime, one*R2_c1_v + R2_r_v*pk_T)

    #PROOF OF DECRYPTION
    R2_sk.value = sk_vs

    #The difference between lv and lvs should be decrypted
    R2_c0 = R2_c0_lv-R2_c0_lvs
    R2_c1 = R2_c1_lv-R2_c1_lvs
    R2_ct = (R2_c0, R2_c1)

    R2_m_dec = dec(R2_ct, R2_sk.value)

    one = Secret(name="one", value=1)
    R2_neg_c0 = (-1)*R2_c0

    #Following the paper, checking that decryption is 0*g
    R2_dec_stmt = DLRep(0*g, one*R2_c1 + R2_sk*R2_neg_c0)

    #SECOND PROOF OF RE-ENCRYPTION
    R2_r_lv.value = order.random()

    R2_reEnc2 = re_enc(g, pk_vs, R2_ct_i, R2_r_lv.value)
    R2_c0_lv_Prime, R2_c1_lv_Prime = R2_reEnc2

    one = Secret(name="one", value=1)

    R2_reenc_stmt2 = DLRep(R2_c0_lv_Prime, one*R2_c0_i + R2_r_lv*g) & DLRep(R2_c1_lv_Prime, one*R2_c1_i + R2_r_lv*pk_vs)


    #THIRD PROOF OF RE-ENCRYPTION
    R2_r_lvs.value = order.random()

    R2_reEnc3 = re_enc(g, pk_vs, R2_ct_i, R2_r_lvs.value)
    R2_c0_lvs_Prime, R2_c1_lvs_Prime = R2_reEnc3

    one = Secret(name="one", value=1)

    R2_reenc_stmt3 = DLRep(R2_c0_lvs_Prime, one*R2_c0_i + R2_r_lvs*g) & DLRep(R2_c1_lvs_Prime, one*R2_c1_i + R2_r_lvs*pk_vs)

    #RELATION 2 STATEMENT
    #Conjoining all sub-proofs.
    stmt = R2_reenc_stmt1 & R2_dec_stmt & R2_reenc_stmt2 & R2_reenc_stmt3

    return stmt, R2_r_v, R2_r_lv, R2_r_lvs, R2_sk

def ballotRandomization3(g, order, sk_vs, pk_T, pk_vs):
    """Constructs all sub-proofs and witnesses for R3

    The order of sub-proofs in this relation is:
        - Proof of Re-Encryption (1)
        - Proof of Decryption w. range proof
        - Proof of Re-Encryption (2)
        - Proof of Re-Encryption (3)
    
    All stand-in encryptions for 'previous' encryption
    are done before constructing the sub-proofs.

    Args:
        g (EcPt): generator of the EC group
        order (Bn): order of the EC group
        sk_vs (Bn): secret key of the Voting Server
        pk_T (EcPt): public key of the Tallier
        pk_vs(EcPt): public key of the Voting Server
    
    Returns:
        stmt (AndProofStmt): the conjoint proof of R3 sub-proofs
        R3_sk (Secret): Prover witness, Voting Server secret key
        R3_r_v (Secret): Prover witness, randomness
        R3_r_lv (Secret): Prover witness, randomness
        R3_r_lvs (Secret): Prover witness, randomness
    """

    #PROVER WITNESSES
    R3_sk = Secret()
    R3_r_v = Secret()
    R3_r_lv = Secret()
    R3_r_lvs = Secret()

    #STAND-IN ENCRYPTIONS
    #Generates previous three encryptions as stated in the paper
    R3_c0_v, R3_c1_v = enc(g, pk_T, 2, order.random())

    #Voter list (lv) and Voting Server list (lvs) instatiated as
    #different values here to accommodate the R3 scenario of a coerced vote
    #lvs is forced to be smaller than lv to avoid a negative range
    lv = bn.Bn(200).random()
    lvs = bn.Bn(200).random()
    if lvs > lv:
        lvs = lv-1

    R3_c0_lv, R3_c1_lv = enc(g, pk_vs, lv, order.random())

    R3_c0_lvs, R3_c1_lvs = enc(g, pk_vs, lvs, order.random())

    #New ciphertext made from encryption of a previous lvs as described
    #in the paper
    R3_c0_i = 2*R3_c0_lvs
    R3_c1_i = 2*R3_c1_lvs

    R3_ct_i = (R3_c0_i, R3_c1_i)


    #FIRST PROOF OF RE-ENCRYPTION
    R3_r_v.value = order.random()

    R3_reEnc1 = re_enc(g, pk_T, (R3_c0_v, R3_c1_v), R3_r_v.value)
    R3_c0_v_Prime, R3_c1_v_Prime = R3_reEnc1

    one = Secret(name="one", value=1)

    R3_reenc_stmt1 = DLRep(R3_c0_v_Prime, one*R3_c0_v + R3_r_v*g) & DLRep(R3_c1_v_Prime, one*R3_c1_v + R3_r_v*pk_T)

    #PROOF OF DECRYPTION
    R3_sk.value = sk_vs

    #The difference between lv and lvs should be decrypted
    R3_c0 = R3_c0_lv - R3_c0_lvs
    R3_c1 = R3_c1_lv - R3_c1_lvs
    R3_ct = (R3_c0, R3_c1)

    R3_m_dec = dec(R3_ct, R3_sk.value)

    one = Secret(name="one", value=1)
    R3_neg_c0 = (-1)*R3_c0

    R3_dec_stmt = DLRep(R3_m_dec, one*R3_c1 + R3_sk*R3_neg_c0) 

    #RANGE PROOF
    #Hot-fix solution to stand-in for Proof of Inequality to check that m /= 0

    #Stand-in secret value for the decrypted message
    m = Secret(value=0)

    #Brute forcing the value of m from the decryption
    for i in range(1,200):
        if R3_m_dec == i*g:
            m.value = i

    R3_range_stmt = RangeOnlyStmt(1, 200, m)

    #SECOND PROOF OF RE-ENCRYPTION
    R3_r_lv.value = order.random()

    R3_reEnc2 = re_enc(g, pk_vs, R3_ct_i, R3_r_lv.value)
    R3_c0_lv_Prime, R3_c1_lv_Prime = R3_reEnc2

    one = Secret(name="one", value=1)

    R3_reenc_stmt2 = DLRep(R3_c0_lv_Prime, one*R3_c0_i + R3_r_lv*g) & DLRep(R3_c1_lv_Prime, one*R3_c1_i + R3_r_lv*pk_vs)


    #THIRD PROOF OF RE-ENCRYPTION
    R3_r_lvs.value = order.random()

    R3_reEnc3 = re_enc(g, pk_vs, R3_ct_i, R3_r_lvs.value)
    R3_c0_lvs_Prime, R3_c1_lvs_Prime = R3_reEnc3

    one = Secret(name="one", value=1)

    R3_reenc_stmt3 = DLRep(R3_c0_lvs_Prime, one*R3_c0_i + R3_r_lvs*g) & DLRep(R3_c1_lvs_Prime, one*R3_c1_i + R3_r_lvs*pk_vs)

    #RELATION 3 STATEMENT
    #Conjoining all sub-proofs.
    stmt = R3_reenc_stmt1 & R3_dec_stmt & R3_range_stmt & R3_reenc_stmt2 & R3_reenc_stmt3

    return stmt, R3_sk, R3_r_v, R3_r_lv, R3_r_lvs

def proofRelation1(relation1, relation2, relation3, R1_v, R1_r_v, R1_lv, R1_r_lv, R1_r_lvs, R1_sk):
    """Generates full proof, for the scenario of proving R1

    Simulates R2 and R3 and generates proof with R1 witnesses.

    Args:
        relation1 (AndProofStmt): the R1 statement of conjointed sub-proofs
        relation2 (AndProofStmt): the R2 statement of conjointed sub-proofs
        relation3 (AndProofStmt): the R3 statement of conjointed sub-proofs
        R1_v (Secret): Prover witness, vote
        R1_r_v (Secret): Prover witness, randomness
        R1_lv (Secret): Prover witness, voter list
        R1_r_lv (Secret): Prover witness, randomness
        R1_r_lvs (Secret): Prover witness, randomness
        R1_sk (Secret): Prover witness, voter secret key
        
    Returns:
        stmt (OrProofStmt): the disjoint proof of all three relations
                            R2 and R3 being simulated
        nizk (NIZK): the non-interactive part of the proof,
                     generating challenge and response
    """

    #Full proof disjoint statement
    stmt = relation1 | relation2 | relation3

    #Setting R2 and R3 to be simulated
    stmt.subproofs[1].set_simulated()
    stmt.subproofs[2].set_simulated()

    #Prover stating R1 witnesses
    nizk = stmt.prove({R1_v: R1_v.value, R1_r_v: R1_r_v.value, R1_lv: R1_lv.value, R1_r_lv: R1_r_lv.value, R1_r_lvs: R1_r_lvs.value, R1_sk: R1_sk.value})

    return stmt, nizk

def proofRelation2(relation1, relation2, relation3, R2_r_v, R2_r_lv, R2_r_lvs, R2_sk):
    """Generates full proof, for the scenario of proving R2

    Simulates R1 and R3 and generates proof with R2 witnesses.

    Args:
        relation1 (AndProofStmt): the R1 statement of conjointed sub-proofs
        relation2 (AndProofStmt): the R2 statement of conjointed sub-proofs
        relation3 (AndProofStmt): the R3 statement of conjointed sub-proofs
        R2_r_v (Secret): Prover witness, randomness
        R2_r_lv (Secret): Prover witness, randomness
        R2_r_lvs (Secret): Prover witness, randomness
        R2_sk (Secret): Prover witness, Voting Server secret key
        
    Returns:
        stmt (OrProofStmt): the disjoint proof of all three relations
                            R1 and R3 being simulated
        nizk (NIZK): the non-interactive part of the proof,
                     generating challenge and response
    """

    #Full proof disjoint statement
    stmt = relation1 | relation2 | relation3

    #Setting R1 and R3 to be simulated
    stmt.subproofs[0].set_simulated()
    stmt.subproofs[2].set_simulated()

    #Prover stating R2 witnesses
    nizk = stmt.prove({R2_r_v: R2_r_v.value, R2_r_lv: R2_r_lv.value, R2_r_lvs: R2_r_lvs.value, R2_sk: R2_sk.value})

    return stmt, nizk

def proofRelation3(relation1, relation2, relation3, R3_sk, R3_r_v, R3_r_lv, R3_r_lvs):
    """Generates full proof, for the scenario of proving R3

    Simulates R1 and R2 and generates proof with R3 witnesses.

    Args:
        relation1 (AndProofStmt): the R1 statement of conjointed sub-proofs
        relation2 (AndProofStmt): the R2 statement of conjointed sub-proofs
        relation3 (AndProofStmt): the R3 statement of conjointed sub-proofs
        R3_sk (Secret): Prover witness, Voting Server secret key
        R3_r_v (Secret): Prover witness, randomness
        R3_r_lv (Secret): Prover witness, randomness
        R3_r_lvs (Secret): Prover witness, randomness
        
    Returns:
        stmt (OrProofStmt): the disjoint proof of all three relations
                            R1 and R2 being simulated
        nizk (NIZK): the non-interactive part of the proof,
                     generating challenge and response
    """

    #Full proof disjoint statement
    stmt = relation1 | relation2 | relation3

    #Setting R1 and R2 to be simulated
    stmt.subproofs[0].set_simulated()
    stmt.subproofs[1].set_simulated()

    #Prover stating R3 witnesses
    nizk = stmt.prove({R3_sk: R3_sk.value, R3_r_v: R3_r_v.value, R3_r_lv: R3_r_lv.value, R3_r_lvs: R3_r_lvs.value})

    return stmt, nizk

def verification(stmt, proof):
    """Verifies full proof

    Args:
        stmt (OrProofStmt): the disjoint proof of all three relations
        proof (NIZK): the non-interactive part of the proof,
                      containing challenge and response
        
    Returns:
        v (bool): returns the result of the verification
    """

    v = stmt.verify(proof)

    return v

def proof(g, order, sk_id, pk_T, sk_vs, pk_vs, relation):
    """Runs an iteration of the full proof

    This function takes the public parameters as well as an indication of
    which relation is proven in this iteration of the proof.
    
    First it constructs the sub-proofs of the three relations by 
    running the three functions for ballot generation and randomization.

    Then an if else statement is used to construct a proof for proving
    the stated relation to be proven.

    Finally the generated proof is verified, the result of which
    are printed.

    Across the whole function, various time stamps are put around key
    operations to measure the running time for the analysis.
    The running times are the output of this function, both in
    print statements and return values.

    Args:
        g (EcPt): generator of the EC group
        order (Bn): order of the EC group
        sk_id (Bn): secret key of the Voter
        pk_T (EcPt): public key of the Tallier
        sk_vs (Bn): secret key of the Voting Server
        pk_vs (EcPt): public key of the Voting Server
        relation (int): input value 1, 2 or 3, indicating the
                        relation to be proven
    
    Returns:
        either:
            ballotGenerationTime (int): time to generate a ballot for R1
        or
            ballotRandomizationTime2 (int): time to randomize a ballot for R2
        or
            ballotRandomizationTime3 (int): time to randomize a ballot for R3
        
        verificationTime (int): time to verify the proof
    """
    
    #CONSTRUCTING THE THREE RELATIONS
    start1 = time.process_time_ns()
    relation1, R1_v, R1_r_v, R1_lv, R1_r_lv, R1_r_lvs, R1_sk = ballotGeneration(g, order, sk_id, pk_T, pk_vs)
    finish1 = time.process_time_ns() - start1

    start2 = time.process_time_ns()
    relation2, R2_r_v, R2_r_lv, R2_r_lvs, R2_sk = ballotRandomization2(g, order, sk_vs, pk_T, pk_vs)
    finish2 = time.process_time_ns() - start2

    start3 = time.process_time_ns()
    relation3, R3_sk, R3_r_v, R3_r_lv, R3_r_lvs = ballotRandomization3(g, order, sk_vs, pk_T, pk_vs)
    finish3 = time.process_time_ns() - start3

    #PROOF GENERATION BASED ON WHICH RELATION IS PROVEN
    if relation == 1:
        startProof1 = time.process_time_ns()
        stmt, proof = proofRelation1(relation1, relation2, relation3, R1_v, R1_r_v, R1_lv, R1_r_lv, R1_r_lvs, R1_sk)
        finishProof1 = time.process_time_ns() - startProof1
        ballotGenerationTime = finish1 + finishProof1
        print("Ballot generation time:", ballotGenerationTime)
    
    elif relation == 2:
        startProof2 = time.process_time_ns()
        stmt, proof = proofRelation2(relation1, relation2, relation3, R2_r_v, R2_r_lv, R2_r_lvs, R2_sk)
        finishProof2 = time.process_time_ns() - startProof2
        ballotRandomizationTime2 = finish2 + finishProof2
        print("Ballot randomization time (R2):", ballotRandomizationTime2)

    elif relation == 3:
        startProof3 = time.process_time_ns()
        stmt, proof = proofRelation3(relation1, relation2, relation3, R3_sk, R3_r_v, R3_r_lv, R3_r_lvs)
        finishProof3 = time.process_time_ns() - startProof3
        ballotRandomizationTime3 = finish3 + finishProof3
        print("Ballot randomization time (R3):", ballotRandomizationTime3)

    #PROOF VERIFICATION
    startVerification = time.process_time_ns()
    v = verification(stmt, proof)
    verificationTime = time.process_time_ns() - startVerification

    print("Relation", relation, "verified: ", v)
    print("Verification time:", verificationTime)

    #PRINTS OUT THE RELEVANT TIMES FOR THE PROVEN RELATION
    if relation ==1:
        return ballotGenerationTime, verificationTime
    elif relation ==2:
        return ballotRandomizationTime2, verificationTime
    elif relation==3:
        return ballotRandomizationTime3, verificationTime



"""============ TIME MEASUREMENT EXAMPLES ============"""



#Ordinary run of the proof showcasing how to run with each relation

#Generating a keypair for a voter
sk_1 = order.random()
pk_1 = sk_vs*g

#Proving R1
proof(g, order, sk_1, pk_T, sk_vs, pk_vs, 1)

#Proving R2
proof(g, order, sk_1, pk_T, sk_vs, pk_vs, 2)

#Proving R3
proof(g, order, sk_1, pk_T, sk_vs, pk_vs, 3)



"""
#Run with multiple voters
#Can be extended by generating more voter key pairs and running
#the proof the same number of times

sk_1 = order.random()
pk_1 = sk_vs*g

sk_2 = order.random()
pk_2 = sk_2*g

time1, v1 = proof(g, order, sk_1, pk_T, sk_vs, pk_vs, 1)
time2, v2 = proof(g, order, sk_2, pk_T, sk_vs, pk_vs, 1)

print("=======")
print("total operation time: ", time1+time2)
print("total verification time: ", v1+v2)
"""