pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/eddsamimc.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

template CommitmentHasher() {
    signal input secret;
    signal input nonce;
    signal output leafHash;

    component leafHasher = Poseidon(2);
  
    leafHasher.inputs[0] <== secret;
    leafHasher.inputs[1] <== nonce;
    //remove the last byte
    leafHash <== leafHasher.out;
}



template sigVerifier(n) {
    signal input identity_pk[2];
    signal input auth_sig_r[2];
    signal input auth_sig_s;

    signal input secret;
    signal input leaf;
    signal input cred_id;


    //ensure msg = H(sk || sNum) and leaf = H(sk || cred_id)
    component msgHasher = CommitmentHasher();
    msgHasher.secret <== secret;
    msgHasher.nonce <== identity_pk[0];
    log(msgHasher.leafHash);

    component leafHasher = CommitmentHasher();
    leafHasher.secret <== secret;
    leafHasher.nonce <== cred_id;
    leafHasher.leafHash === leaf;


    component sig_verifier = EdDSAMiMCVerifier();
    1 ==> sig_verifier.enabled;
    identity_pk[0] ==> sig_verifier.Ax;
    identity_pk[1] ==> sig_verifier.Ay;
    auth_sig_r[0] ==> sig_verifier.R8x;
    auth_sig_r[1] ==> sig_verifier.R8y;
    auth_sig_s ==> sig_verifier.S;
    msgHasher.leafHash ==> sig_verifier.M;
} 


component main {public [identity_pk, leaf, cred_id]} = sigVerifier(20);