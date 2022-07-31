//here fill in this template for all required contracts
var treeManager = artifacts.require("treeManager");
var verifier = artifacts.require("Verifier");
var sybilResistantProtocol = artifacts.require("sybilResistantProtocol");
var hasher_address = "0x4e9aa9d356753509991e3be0608b89a28904029e"

module.exports = function(deployer) {
  deployer.then(async () => {
    await deployer.deploy(verifier);
    await deployer.deploy(sybilResistantProtocol, verifier.address, "0x7c5A82D513fAA13c160871A36F4F5A711a9b1506");
    //...
});
};
