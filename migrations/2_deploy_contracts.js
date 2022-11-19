const ChatApp = artifacts.require("Chat");

module.exports = (deployer) => {
    deployer.deploy(ChatApp);
}