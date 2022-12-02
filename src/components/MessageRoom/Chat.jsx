import React, { useEffect, useState } from 'react'
import Input from './Input'
import Messages from './Messages'

const ChatUI = () => {
  const [addr, setAddr] = useState([]);
  useEffect(() => {
    fetch('/chat/chatAddress')
      .then(res => res.json())
      .then(setAddr);
  }, []);
  return (
    <div className='chatui'>
        <span className="chatHeader">addr</span>
        {addr.map(x => <Messages address={x} />)}
        <Input/>
    </div>
  )
}

export default ChatUI