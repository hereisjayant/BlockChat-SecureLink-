import React, { useEffect, useState } from 'react';
import logo from '../logo.png';
import Web3 from 'web3';
import './App.css';

const App = () => {
  const [connected, setConnected] = useState(false);
  const [address, setAddress] = useState(null);
  
  useEffect(() => {
    loadEverything();
  }, []);

  const loadEverything = () => {
    loadWeb3();
  }

  const loadWeb3 = async () => {
    if (window.ethereum) { // if metamask exists
      try {
        console.log("Connecting to Metamask wallet...");
        const address = await window.ethereum.enable();
        setConnected(true);
        setAddress(address);

        console.log("Connecting to local Ganache chain...");
        window.web3 = new Web3(Web3.providers.WebsocketProvider("ws://localhost:7545"));
      }
      catch (err) {
        console.error(err);
        setConnected(false);
      }
    } else if (window.web3) {
      window.web3 = new Web3(window.web3.currentProvider);
    } else {
      setConnected(false);
      console.error("No metamask or existing web3 provider detected")
    }
  }

  return (
    <div>
      HELLO
    </div>
  )
}

export default App;
