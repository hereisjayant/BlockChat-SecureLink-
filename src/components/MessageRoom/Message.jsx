import React from 'react'

const Message = (props) => {
  const msg = props.msg;
  if (msg.youSent)
    return (
        <div className='message owner'>
          <div className="messageContent">
              {<p>`${msg.msg}`</p>}
          </div>
      </div>
    );
  else
      return (
        <div className='message'>
          <div className="messageContent">
          {<p>`${msg.msg}`</p>}
          </div>
      </div>
      );
}

export default Message