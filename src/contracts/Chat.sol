pragma solidity >=0.4.21 <0.6.0;

contract Chat {
    string public name = "black-hat-chat";

    event messageSentEvent(address indexed from, address indexed to, string message);

    function sendMessage(address to, string memory message) public {
        emit messageSentEvent(msg.sender, to, message);
    }

}