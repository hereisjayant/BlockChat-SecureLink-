import React from 'react'
import Input from './Input'
import Messages from './Messages'

const ChatUI = () => {
  return (
    <div className='chatui'>
        <span className="chatHeader">BOB</span>
        <Messages/>
        <Input/>
    </div>
  )
}

export default ChatUI