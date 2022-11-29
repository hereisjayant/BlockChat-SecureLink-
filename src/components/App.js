import React, { useEffect, useState } from 'react';
import Web3 from 'web3';
import './App.css';

import Messenger from "../services/chat";
import MessageRoom from "./MessageRoom/index";

const App = () => {
  const [isConnected, setIsConnected] = useState(false);
  const [userPubAddress, setUserPubAddress] = useState(null);
  const [userBalance, setUserBalance] = useState(0);

  const [messenger, setMessenger] = useState(null);
  
  useEffect(() => {
    loadEverything();
  }, []);

  const loadEverything = async () => {
    await loadMessenger();
    await loadWeb3();
  }

  // This is where things start going downhill
  const loadMessenger = async () => {
    try {
      const m = new Messenger();
      await m.generateDH();
      let pkr = m.getDHPublicKey();
      await m.generateRootKey(pkr);
      // await m.generateDH();
      // pkr = m.getDHPublicKey();
      setMessenger(m);
      console.log({ m })
    } catch (err) {
      console.error("error loading messenger!", err);
    }
  }

  const loadWeb3 = async () => {
    if (window.ethereum) { // if metamask exists
      try {
        console.log("Connecting to Metamask wallet...");
        const address = (await window.ethereum.request({ method: 'eth_requestAccounts' }))[0];
        setUserPubAddress(address);

        console.log(`Connecting to local Ganache chain with address ${address}... `);
        const wsProvider = new Web3.providers.WebsocketProvider("ws://localhost:7545");
        window.web3 = new Web3(wsProvider);

        console.log("Loading address data...");
        const ethBalance = await window.web3.eth.getBalance(address);
        setUserBalance(ethBalance);

        setIsConnected(true);
      }
      catch (err) {
        if (err.code === 4001) {
          // EIP-1193 userRejectedRequest error
          // If this happens, the user rejected the connection request.
          console.error('User denied wallet access!', err);
        }
        else {
          console.error(err);
        }
        setIsConnected(false);
      }
    } else if (window.web3) {
      window.web3 = new Web3(window.web3.currentProvider);
    } else {
      setIsConnected(false);
      console.error("No metamask or existing web3 provider detected");
    }
  }

  return (
    <div>
      <h1>Current Address: {userPubAddress}</h1>
      <div>Balance: {userBalance}</div>
      {isConnected &&
        <MessageRoom
          messenger={messenger}
          userAddress={userPubAddress}
        />
      }
    </div>
  )
}

export default App;
