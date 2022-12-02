import React, { useEffect, useState } from 'react'
import Message from './Message'

async function Messages(props) {
  const [messages, setMessages] = useState([]);
  useEffect(() => {
    fetch(`/chat/messages/${props.address}`)
      .then(res => res.json())
      .then(x => {console.log(x); setMessages(x)});
  }, []);
  return (
    <div className='messages'>
        {messages.map(x => <Message msg = {x} />)}
    </div>
  )
}

export default Messages