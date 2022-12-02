import React, { useEffect, useState } from 'react'
import ChatUsers from './ChatUsers'
import Navbar  from './Navbar'
import SearchUser from './Search'

const Sidebar = (props) => {
  const [pastChatters, setChatters] = useState([]);

  useEffect(() => {
    fetch('/chat/chatAddress')
      .then(res => res.json())
      .then(setChatters);
  }, []);

  return (
    <div className='sidebar'>
        <Navbar/>
        <SearchUser searchUser={}/>
        {pastChatters.map(x => <ChatUsers onClick={this.click} addr={x} />)}
    </div>
  )
}

export default Sidebar