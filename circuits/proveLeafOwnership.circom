include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "merkleTree.circom";

// computes Poseidon(secret + nonce) - output is 248 bits
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


// Verifies that H(sk||r) = L and L is in the tree
template ProofOfOwnership(levels) {
    signal input root;
    signal input secret;
    signal input credential_identifier;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input wallet_address;
    signal input protocol_address;
    signal output userprotocolhash;
    //leaf not needed as an input - leaf is calculated from commitment hasher

    component hasher = CommitmentHasher();
    hasher.secret <== secret;
    hasher.nonce <== credential_identifier;
    log(hasher.leafHash);
    component tree = MerkleTreeInclusionProof(levels);
    tree.leaf <== hasher.leafHash;
    
    
    for (var i = 0; i < levels; i++) {
        tree.siblings[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    tree.root === root;

    component hasher1 = CommitmentHasher();
    hasher1.nonce <== protocol_address;
    hasher1.secret <== secret;

    // Dummy square to prevent tampering wallet_address.
    signal wallet_addressSquared;
    wallet_addressSquared <== wallet_address * wallet_address;

    userprotocolhash <== hasher1.leafHash;
}

component main {public [root, credential_identifier, protocol_address, wallet_address]} = ProofOfOwnership(20);