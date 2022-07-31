include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "merkleTree.circom";

// computes Poseidon(secret + nonce) - output is 248 bits
template CommitmentHasher() {
    signal input nonce;
    signal input secret;
    signal output leafHash;

    component leafHasher = Poseidon(2);
  
    leafHasher.inputs[0] <== secret;
    leafHasher.inputs[1] <== nonce;
    //remove the last byte
    component toBits = Num2Bits(256);
    toBits.in <== leafHasher.out;
    component toNum = Bits2Num(248);
    for (var i = 0; i < 248; i++) {
        toNum.in[i] <== toBits.out[i];
    }
    
    leafHash <== toNum.out;
}


// Verifies that H(sk||r) = L and L is in the tree
//This proof is used to verify that a user is a human once their leaf has been added to a server
template ProofOfMembership(levels) {
    signal input root;
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input protocol_address;
    signal output userprotocolhash;
    //leaf not needed as an input - leaf is calculated from commitment hasher
    component nonceHash = CommitmentHasher();
    nonceHash.secret <== secret;
    nonceHash.nonce <== secret;

    component hasher = CommitmentHasher();
    hasher.nonce <== nonceHash.leafHash;
    hasher.secret <== secret;
    log(hasher.leafHash);
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== hasher.leafHash;
    tree.root <== root;
    
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }

    component hasher1 = CommitmentHasher();
    hasher1.nonce <== protocol_address;
    hasher1.secret <== secret;
    userprotocolhash <== hasher1.leafHash;
    // output a nullifier hash of user's sk + protocol hash
    
    
}

component main {public [root, protocol_address]} = ProofOfMembership(20);