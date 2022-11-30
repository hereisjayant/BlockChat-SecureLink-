const crypto = windows.crypto;
// replacement should be something like
// const crypto = windows.crypto
const subtle = crypto.subtle;



/**
 * Messenger module to encrypt/encrypt messages between users
 * 
 * Inspired by Signal Protocol (https://signal.org/docs/specifications/doubleratchet)
 * 
 * To start conversation:
 *  1. Establish Root Key
 *      a. Can use X3DH but in this case can 
 *          `computeDH()` -> Send Public DH key with `getPublicKey` -> Compute Root and ChainKeyS with `receivePublicKey`
 *  2. Use `Messenger.ratchetEncrypt` and `Messenger.ratchedDecrypt` to encrypt/decrypt messages
 * 
 */
class Messenger
{
    constructor(address)
    {
        this.address = address  // Address of user to talk to
        this.dhsKeys = null;    // DH Private and Public Key pair
        this.dhrPK = null;      // Received Public Key pair from other user
        this.rootKey = null;    // Root key used to establish Root Ratchet
        this.chainKeyS = null;  // chainKeyS and chainKeyR used for send/receive ratchet 
        this.chainKeyR = null;  
        this.n_s = 0;           // Number of messages sent
        this.n_r = 0;           // Number of messages received
        this.p_n = 0;           // Number of messages of previous sending chain
        this.msSkip = [];       // List of skipped over message keys

        this.HMAC = {
            name: 'HMAC',
            hash: 'SHA-256',
        };
        let temp = []
        for (let i = 0; i < 32; i++)
            temp.push(0);
        this.salt0 = new Uint8Array(temp);
        const txtEnc = new TextEncoder();
        this.infoCKS = txtEnc.encode('ChainKeyS');
        this.infoMsgKey = txtEnc.encode('MessageKey');
        this.infoKeyInit = txtEnc.encode('KeyInit');
        this.keySizeBits = 256;
    }

    /**
     * Create and import new Messenger object
     * @param {Object} imported Stored JSON object containing JSON.parse() Messenger attributes
     * @returns new Messenger object with attributes set by `imported`
     */
    static async import(imported)
    {
        const messenger = new Messenger();
        const makeUint8Buf = (x) => Uint8Array.from(Buffer.from(x, 'hex'));
        messenger.address = imported.address;
        messenger.dhsKeys = {
            privateKey: await subtle.importKey('pkcs8', makeUint8Buf(imported.dhsKeys.privateKey), {name: 'X25519'}, true, ['deriveKey', 'deriveBits']),
            publicKey: await subtle.importKey('spki', makeUint8Buf(imported.dhsKeys.publicKey), {name: 'X25519'},true, ['deriveKey', 'deriveBits']),
        };
        messenger.dhrPK = await subtle.importKey('spki', makeUint8Buf(imported.dhrPK), {name: 'X25519'}, true, ['deriveKey', 'deriveBits']);
        messenger.rootKey = makeUint8Buf(imported.rootKey);
        messenger.chainKeyS = await subtle.importKey('jwk', imported.chainKeyS, messenger.HMAC, true, ['sign', 'verify']);
        messenger.chainKeyR = await subtle.importKey('jwk', imported.chainKeyR, messenger.HMAC, true, ['sign', 'verify']);
        messenger.n_s = imported.n_s;
        messenger.n_r = imported.n_r;
        messenger.p_n = imported.p_n;
        messenger.msSkip = JSON.parse(JSON.stringify(imported.msSkip));

        return messenger;
    }

    /*
     * Generates Diffie-Hellman Key Exchange using Curve25519 
     * Stores key pair into this.dhsKeys
     */
    async generateDH()
    {
        this.dhsKeys = await subtle.generateKey({
            name: 'X25519'
        }, true, ['deriveKey', 'deriveBits']);
    }

    /**
     * Returns DH Public key
     * @returns DH Public Key in 'spki-pem' form
     */
    async getDHPublicKey()
    {
        return await subtle.exportKey('spki', this.dhsKeys.publicKey);
    }

    /**
     * Converts Raw Buffer in 'spki' to X25519 Key
     * @param {Buffer | string} key 
     * @returns X25519 Crypto Key
     */
    async convertKeyX25519(key)
    {
        if (typeof(key) == 'string')
            key = Buffer.from(key, 'hex');
        return await subtle.importKey('spki', key, {name: 'X25519'}, true, ['deriveBits', 'deriveKey']);
    }

    /**
     * Uses given public key to compute chainKeyS and rootKey
     * @param {string} publicKey DH Public Key in 'spki-pem' format 
     */
    async receivePublicKey(publicKey)
    {
        if (typeof(publicKey) != 'string')
            publicKey = Buffer.from(publicKey).toString('hex');
        this.dhrPK = publicKey;
        const {chainKey, rootKey} = await this.kdfRK();
        this.rootKey = rootKey;
        this.chainKeyS = chainKey;
    }

    /**
     * Takes given key and returns it as 'HKDF' key meant with 'deriveKey' and 'deriveBits' usage
     * @param {Buffer | ArrayBuffer} key Buffer containing raw bytes of key 
     * @returns <CryptoKey> form of 'key' 
     */
    async convertToHKDF(key)
    {
        return await subtle.importKey
        (
            'raw',
            key,
            {name: 'HKDF'},
            false,
            ['deriveKey', 'deriveBits']
        );
    }

    /**
     * Converts given key into 'HMAC' key meant to 'sign' or 'verify'
     * hash: SHA-256 with `sign` and `verify` usage
     * @param {Buffer | ArrayBuffer} key Buffer containing raw bytes of key  
     * @returns <CryptoKey> form of 'key'
     */
    async convertToHMAC(key)
    {
        return await subtle.importKey
        (
            'raw',
            key,
            this.HMAC,
            true,
            ['sign', 'verify']
        )
    }

    /**
     * Generates root key only using `publicKey`
     * Meant to be used to establish inital Root Key for Root Ratchet
     * @param {string} publicKey Public Key in 'spki-pem' format
     */
    async generateRootKey(publicKey)
    {
        const key = await subtle.deriveBits(
            {
                name: 'X25519',
                public: await this.convertKeyX25519(publicKey),
            }, 
            this.dhsKeys.privateKey,
            null
        );
        this.rootKey = key;
    }

    /**
     * Computes DH secret key using this.dhrPK (received public key) and this.dhsKeys.privateKey
     * @returns <CryptoKey> with `HKDF` type
     */
    async computeDH()
    {
        const keyBits = await subtle.deriveBits(
            {
                name: 'X25519',
                public: await this.convertKeyX25519(this.dhrPK),
            }, 
            this.dhsKeys.privateKey,
            null,
        );
        return await this.convertToHKDF(keyBits);
    }

    /**
     * Takes given key to compute keys needed for encryption/decryption and signing/verifying
     * Following reccomendations from Signal Documentation 
     *  (https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms)
     * Uses AES-256-CBC encryption and SHA-256 for signature
     * @param {CryptoKey} messageKey type `HKDF` with `deriveKey` usage
     * @returns {`encryptKey`, `iv`, `authKey`} Used to encrypt/decrypt and sign/verify messages 
     */
    async generateEncryptKeys(messageKey)
    {
        const neededBits = 80 * 8;
        messageKey = await this.convertToHKDF(messageKey);
        const key_init = await subtle.deriveBits
        (
            {
                name: 'HKDF',
                hash: 'SHA-256',
                info: this.infoKeyInit,
                salt: this.salt0,
            },
            messageKey,
            neededBits,
        );
        let encryptKey = key_init.slice(0, 32);
        let authKey = key_init.slice(32, 64);
        let iv = key_init.slice(64, 80);
        encryptKey = await subtle.importKey
        (
            'raw',
            encryptKey,
            {name: 'AES-CBC'},
            false,
            ['encrypt', 'decrypt']
        );
        authKey = await subtle.importKey
        (
            'raw',
            authKey,
            this.HMAC,
            false,
            ['sign', 'verify']
        );
        return {encryptKey, iv, authKey}
    }

    /**
     * Computes Chain Key and Root key using prexisting root key and computed DH from other party's public key
     * Uses HKDF with SHA-256
     * @returns {`chainKey`, `rootKey`} Chainkey and new root key for ratchet
     */
    async kdfRK()
    {
        const keyBits = await subtle.deriveBits
        ( 
            {
                name: 'HKDF',
                hash: 'SHA-256',
                info: this.infoCKS,
                salt: this.rootKey
            },
            await this.computeDH(),
            this.keySizeBits,
        );
        const chainKey = await this.convertToHMAC(keyBits);
        const rootKey = keyBits;
        return {chainKey, rootKey}
    }

    /**
     * Computes chain key using given `inputkey` to compute next chain key and message key
     * @param {CryptoKey} inputKey 
     * @returns {{chainKey: CryptoKey, messageKey: CryptoKey}} chainKey and messageKey of `HMAC` type
     */
    async kdfCK(inputKey)
    {
        // According to Signal, the input to the HMAC can be a fixed constant (1 for chain key; 2 for message key) signed with `inputKey`
        const chainKeySInput = new Uint8Array(1);
        chainKeySInput[0] = 1;
        const msgKeyInput = new Uint8Array(1);
        msgKeyInput[0] = 2;

        let chainKey = await this.convertToHMAC(await subtle.sign
            ( 
                {name: 'HMAC'},
                inputKey,
                chainKeySInput
            )
        );
        
        let messageKey = await subtle.sign
            (
                {name: 'HMAC'},
                inputKey,
                msgKeyInput,
            );
        return {chainKey, messageKey}
    }

    /**
     * Encodes header as bytes
     * @param {{header: Object, cipherText: }} header 
     * @returns Buffer containing encoded header
     */
    encodeHeader(header)
    {
        return (new TextEncoder).encode(JSON.stringify(header));
    }

    /**
     * Decrypts a given ciphertext using `messageKey`
     * Also checks for integrity and authentication by verifying the `header` matches the `hashHeader`
     * @param {CryptoKey} messageKey Key to decrypt
     * @param {Buffer} cipherText Encrypted message
     * @param {{publicKey: string, p_n: number, n: number}} header Message header
     * @param {Buffer} hashHeader SHA-256 hashed header
     * @throws Error if integrity check fails
     * @returns Decrypted plaintext  
     */
    async decryptMsg(messageKey, cipherText, header, hashHeader)
    {
        const {iv, encryptKey, authKey} = await this.generateEncryptKeys(messageKey);
        // Integrity check
        const verified = await subtle.verify(
            {name: 'HMAC'},
            authKey,
            hashHeader,
            this.encodeHeader(header) + Buffer.from(cipherText).toString('hex')
        );
        if (!verified)
            throw `Message Integrity Error; Message No: ${this.n_r}`;

        const plainBytes = await subtle.decrypt(
            {name: 'AES-CBC', iv},
            encryptKey,
            cipherText
        );
        return (new TextDecoder).decode(plainBytes);
    }

    /**
     * Encrypts a given message for sending
     * @param {string} plaintext 
     * @returns {header: {publicKey: string, p_n: number, n: number}, cipherText: Buffer, hashHeader: Buffer}
     */
    async ratchetEncrypt(plaintext)
    {
        const {chainKey, messageKey} = await this.kdfCK(this.chainKeyS);
        this.chainKeyS = chainKey;

        /**
         * ad (Associated Data) is required for AEAD encryption
         * Following (https://signal.org/docs/specifications/doubleratchet/#double-ratchet),
         * we fix it to a constant (0) since we should be using different message keys for each message
         * The other values `p_n` and `n` are used to help determine how far to move the 
         * sending and receiving chain ratchets in case of out of order messages
         */
        let header = {
            ad: 0,
            publicKey: Buffer.from(await this.getDHPublicKey()).toString('hex'),
            p_n: this.p_n,
            n: this.n_s,
        };
        this.n_s += 1;
        const {iv, encryptKey, authKey} = await this.generateEncryptKeys(messageKey);
        let cipherText = await subtle.encrypt
        (
            {
                name: 'AES-CBC',
                iv: iv
            },
            encryptKey,
            plaintext
        );
        const hashHeader = await subtle.sign({name: 'HMAC'}, authKey, this.encodeHeader(header) + Buffer.from(cipherText).toString('hex'));

        return {header, cipherText, hashHeader};
    }

    /**
     * Decrypts given message 
     * If message was skipped or sent out of order, it will adjust ratchets accordingly
     * @param {{publicKey: string, p_n: number, n: number}} header Message header
     * @param {Buffer} cipherText Encrypted message
     * @param {Buffer} hashHeader Hashed message header
     * @returns Decrypted plaintext
     */
    async ratchetDecrypt(header, cipherText, hashHeader)
    {
        // Check if message corresponds to a skipped message
        const plainTextBytes = await this.trySkippedMessageKeys(header, cipherText, hashHeader);
        if (plainTextBytes)
            return plainTextBytes;
        // If new ratchet key was recevied then it stores skipped message keys from receiving chain 
        // and resets DH, sending, and receiving ratchet
        if (!this.dhrPK || header.publicKey != this.dhrPK)
        {
            await this.skipMessageKeys(header.p_n);
            await this.setUpDHRatchet(header);
        }
        await this.skipMessageKeys(header.n);
        // Advances ratchet to retrieve necessary keys to decrypt message
        const {chainKey, messageKey} = await this.kdfCK(this.chainKeyR);
        this.n_r += 1;
        this.chainKeyR = chainKey
        return await this.decryptMsg(messageKey, cipherText, header, hashHeader);
    }

    /**
     * Checks if given message was skipped and the key to decrypt was stored in `this.msSkip`
     * If message was skipped then it will delete its corresponding key from `this.msSkip`
     * @param {{publicKey: string, p_n: number, n: number}} header Message header
     * @param {Buffer} cipherText Encrypted message
     * @param {Buffer} hashHeader Hashed message header
     * @returns null if message was not skipped or <string> of plaintext if old message key was found
     */
    async trySkippedMessageKeys(header, cipherText, hashHeader)
    {
        let index = this.msSkip.findIndex(i => i.publicKey == header.publicKey && i.n == header.n);
        if (index > -1)
        {
            const messageKey = Buffer.from(this.msSkip[index].msgKey, 'hex');
            this.msSkip.splice(index, 1);
            return await this.decryptMsg(messageKey, cipherText, header, hashHeader);
        }
        return null;
    }

    /**
     * Advances chain key ratchet using previously sent `chainKeyR` and current `chainKeyS` to compute key necessary for decryption 
     * @param {number} until Number of messages in previous sending chain
     */
    async skipMessageKeys(until)
    {
        if (this.chainKeyR != null)
        {
            while (this.n_r < until)
            {
                const {chainKey, messageKey} = await this.kdfCK(this.chainKeyR);
                this.chainKeyR = chainKey;
                const hexMsgKey = Buffer.from(messageKey).toString('hex');
                this.msSkip.push({publicKey: this.dhrPK, msgKey: hexMsgKey, n: this.n_r});
                this.n_r += 1;
            }
        }
    }

    /**
     * Resets Diffie-Hellman key ratchet given header
     * Also resets chain key ratchets for sending and receiving
     * @param {{publicKey: string, p_n: number, n: number}} header Message header
     */
    async setUpDHRatchet(header)
    {
        this.p_n = this.n_s;
        this.n_s = 0;
        this.n_r = 0;
        this.dhrPK = header.publicKey;
        let keyPair = await this.kdfRK();
        this.rootKey = keyPair.rootKey;
        this.chainKeyR = keyPair.chainKey;
        await this.generateDH();
        keyPair = await this.kdfRK();
        this.rootKey = keyPair.rootKey;
        this.chainKeyS = keyPair.chainKey;
    }

    /**
     * Export Messenger object as JSON string
     * @returns JSON string
     */
    async export()
    {
        return JSON.stringify({
            address: this.address,
            dhsKeys: {
                publicKey: Buffer.from(await subtle.exportKey('spki', this.dhsKeys.publicKey)).toString('hex'), 
                privateKey: Buffer.from(await subtle.exportKey('pkcs8', this.dhsKeys.privateKey)).toString('hex')
            },
            dhrPK: this.dhrPK,
            rootKey: Buffer.from(this.rootKey).toString('hex'),
            chainKeyS: await subtle.exportKey('jwk', this.chainKeyS),
            chainKeyR: await subtle.exportKey('jwk', this.chainKeyR),
            n_s: this.n_s,
            n_r: this.n_r,
            p_n: this.p_n,
            msSkip: this.msSkip.map(x => {return {publicKey: x.publicKey, msgKey: x.msgKey, n: x.n}}),
        });
    }
}

const main = async () => {
    let a = new Messenger('alice');
    let b = new Messenger('bob');
    await a.generateDH();
    await b.generateDH();
    let apkr = await a.getDHPublicKey();
    let bpkr = await b.getDHPublicKey();
    await a.generateRootKey(bpkr);
    await b.generateRootKey(apkr);

    await a.generateDH();
    await b.generateDH();
    bpkr = await b.getDHPublicKey();
    await a.receivePublicKey(bpkr);
    let ct = await a.ratchetEncrypt('a');
    console.log(await b.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await b.ratchetEncrypt("b");
    console.log(await a.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await a.ratchetEncrypt("a");
    console.log(await b.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await a.ratchetEncrypt("a");
    console.log(await b.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await a.ratchetEncrypt("a");
    console.log(await b.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await a.ratchetEncrypt("a");
    console.log(await b.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await a.ratchetEncrypt("a");
    console.log(await b.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await b.ratchetEncrypt("b");
    console.log(await a.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await b.ratchetEncrypt("b");
    console.log(await a.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await b.ratchetEncrypt("b");
    console.log(await a.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await a.ratchetEncrypt("a");
    console.log(await b.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await b.ratchetEncrypt("start export");
    console.log(await a.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    let msg1 = await a.ratchetEncrypt("msg1");
    let msg2 = await a.ratchetEncrypt("msg2");
    let msg3 = await a.ratchetEncrypt("msg3");
    let msg4 = await a.ratchetEncrypt("msg4");
    console.log(await b.ratchetDecrypt(msg4.header, msg4.cipherText, msg4.hashHeader));
    console.log(b.msSkip.length);
    const bstr = await b.export();
    b = await Messenger.import(JSON.parse(bstr));
    console.log(await b.ratchetDecrypt(msg3.header, msg3.cipherText, msg3.hashHeader));
    console.log(b.msSkip.length);
    console.log(await b.ratchetDecrypt(msg2.header, msg2.cipherText, msg2.hashHeader));
    console.log(b.msSkip.length);
    console.log(await b.ratchetDecrypt(msg1.header, msg1.cipherText, msg1.hashHeader));
    console.log(b.msSkip.length);
    const astr = await a.export();
    a = await Messenger.import(JSON.parse(astr));
    ct = await b.ratchetEncrypt('DONE');
    console.log(await a.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
    ct = await a.ratchetEncrypt('CONFIRMED');
    console.log(await b.ratchetDecrypt(ct.header, ct.cipherText, ct.hashHeader));
};

// main();

export default Messenger;

