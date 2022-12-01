import React from 'react'
import ChatUsers from './ChatUsers'
import Navbar  from './Navbar'
import SearchUser from './Search'

const Sidebar = () => {
  return (
    <div className='sidebar'>
        <Navbar/>
        <SearchUser/>
        <ChatUsers/>
    </div>
  )
}

export default Sidebar