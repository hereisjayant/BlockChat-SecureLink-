pragma solidity >=0.4.21 <0.6.0;
pragma experimental ABIEncoderV2;

contract Chat {
    string public name = "black-hat-chat";

    struct Message {
        string message;
        address from;
    }

    mapping(address => mapping(address => Message[])) public messages;

    event messageSentEvent(
        address indexed from,
        address indexed to,
        string message
    );

    event messagesFetchAllEvent(
        address indexed from,
        address indexed to,
        Message[] messages
    );

    function sendMessage(address to, string memory message) public {
        messages[msg.sender][to].push(Message(message, msg.sender));
        messages[to][msg.sender].push(Message(message, msg.sender));
        emit messageSentEvent(msg.sender, to, message);
    }

    function getAllMessages(address to) public {
        if (messages[msg.sender][to].length != 0) {
            emit messagesFetchAllEvent(msg.sender, to, messages[msg.sender][to]);
        } else {
            emit messagesFetchAllEvent(msg.sender, to, messages[to][msg.sender]);
        }
    }
}
