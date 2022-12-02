import React, { useEffect, useState } from 'react'
import ChatUsers from './ChatUsers'
import Navbar  from './Navbar'
import SearchUser from './Search'

const Sidebar = ({
  addresses,
  newRecipient
}) => {
  const [pastChatters, setChatters] = useState([]);

  useEffect(() => {
    fetch('/chat/chatAddress')
      .then(res => res.json())
      .then(setChatters);
  }, []);

  return (
    <div className='sidebar'>
        <Navbar/>
        {/* <SearchUser searchUser=""/> */}
        {addresses.map(x => <ChatUsers
          handleClick={() => { newRecipient(x) }}
          addr={x}
          />)}
    </div>
  )
}

export default Sidebar