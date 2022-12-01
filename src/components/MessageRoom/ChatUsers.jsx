import React from 'react'

function ChatUsers() {
  return (
    <div className="chats">
        <div className="userChat">
            <div className="userChatInfo">
            <span>BOB</span>
            <p>Last Message</p>
            </div>
        </div>

        <div className="userChat">
            <div className="userChatInfo">
            <span>Trudy</span>
            <p>Last Message</p>
            </div>
        </div>

        <div className="userChat">
            <div className="userChatInfo">
            <span>User</span>
            <p>Last Message</p>
            </div>
        </div>
    </div>
  )
}

export default ChatUsers