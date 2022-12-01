import express from 'express';
import Messenger from '../services/chat.js';

const router = express.Router();
const allMessengers = [];

const getMessenger = (address) => allMessengers.find(x => x.address == address);

router
    /**
     * Create Messenger to talk to new person; Each person should only have one messenger
     * @param {string} address Address to create Messenger for
     */
    .post('/createChat/:address', async (req, res) => {
        const messenger = new Messenger(req.params.address);
        await messenger.generateDH();
        allMessengers.push(messenger);
        return res.sendStatus(200);
    })

    /**
     * Get public key from Messenger with given address
     * @param {string} address Address of person to send key to
     */
    .get('/getPublicKey/:address', async (req, res) => {
        const messenger = getMessenger(req.params.address);
        if (messenger)
        {
            const key = await messenger.getDHPublicKey();
            return res.status(200).json({success: true, key: key});
        } else 
            return res.status(400).json({success: false});
    })

    /**
     * Generate root key given public key
     * @bodyParam {string} key Public DH key
     * @bodyParam {string} address Address of user
     */
    .put('/genRootKey', async (req, res) => {
        const messenger = getMessenger(req.body.address);
        if (messenger)
        {
            await messenger.generateRootKey(req.body.key);
            await messenger.generateDH();
            return res.sendStatus(200);
        } else
            return res.sendStatus(400);
    })

    /**
     * Generate DH key
     * Should be called after generating root key
     * @bodyParam {string} key Public DH key
     * @bodyParam {string} address Address of user
     */
    .put('/receivePublicKey', async (req, res) => {
        const messenger = getMessenger(req.body.address);
        if (messenger)
        {
            await messenger.receivePublicKey(req.body.key);
            return res.sendStatus(200);
        } else
            return res.sendStatus(400);
    })

    /**
     * Encrypt message to send to address
     * @bodyParam {string} address Address of user
     * @bodyParam {string} message Plaintext to encrypt
     * @return {{header, cipherText, hashHeader}} Encrypted Message
     */
    .post('/encryptMessage', async (req, res) => {
        const m = getMessenger(req.body.address);
        if (m)
        {
            const {header, cipherText, hashHeader} = await m.ratchetEncrypt(req.body.message);
            return res.status(200).json({success: true, header: header, ciphertext: cipherText, hashHeader: hashHeader});
        } else
            return res.status(400).json({success: false});
    })

    /**
     * Decrypt message sent by person
     * @bodyParam {string} address Address of user
     * @bodyParam {object} header Message header
     * @bodyParam {string} cipherText
     * @bodyParam {string} hashHeader
     * @return {{header, cipherText, hashHeader}} Encrypted Message
     */
    .post('/decryptMessage', async (req, res) =>{
        const m = getMessenger(req.body.address);
        if (m)
        {
            const plainText = await m.ratchetDecrypt(req.body.header, req.body.ciphertext, req.body.hashHeader);
            return res.status(200).json({success: true, plainText: plainText});
        } else
            return res.status(400).json({success: false});
        
    })

export default router;