const crypto = require("crypto");
const subtle = crypto.subtle;

class Messenger
{
    constructor()
    {
        this.dhsKeys = null;
        this.dhrPK = null;
        this.rootKey = null;
        this.chainKeyS = null;
        this.chainKeyR = null;
        this.n_s = 0;
        this.n_r = 0;
        this.p_n = 0;
        this.msSkip = [];
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

    async generateDH()
    {
        this.dhsKeys = crypto.generateKeyPairSync(
            'x25519',
            {publicKeyEncoding: {type: 'spki', format: 'pem'}}
        );
    }

    getDHPublicKey()
    {
        return this.dhsKeys.publicKey;
    }

    async receivePublicKey(publicKey)
    {
        this.dhrPK = publicKey;
        const {chainKey, rootKey} = await this.computeChainKey();
        this.rootKey = rootKey;
        this.chainKeyS = chainKey;
    }

    async convertToX25519(key, extractable=false)
    {
        return await subtle.importKey
        (
            'raw',
            key,
            {name: 'X25519'},
            extractable,
            ['deriveKey', 'deriveBits']
        );
    }

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

    async convertToHMAC(key)
    {
        return await subtle.importKey
        (
            'raw',
            key,
            {name: 'HMAC', hash: 'SHA-256'},
            false,
            ['sign', 'verify']
        )
    }

    async generateRootKey(publicKey)
    {
        const keyBits = crypto.diffieHellman(
            {
                publicKey: crypto.createPublicKey(publicKey),
                privateKey: this.dhsKeys.privateKey
            }
        )
        this.rootKey = keyBits;
    }

    async computeDH()
    {
        const keyBits = crypto.diffieHellman(
            {
                publicKey: crypto.createPublicKey(this.dhrPK),
                privateKey: this.dhsKeys.privateKey
            }
        );
        return await this.convertToHKDF(keyBits);
    }

    async generateEncryptKeys(messageKey)
    {
        const neededBytes = 80;
        const key_init = await subtle.deriveBits
        (
            {
                name: 'HKDF',
                hash: 'SHA-256',
                info: this.infoKeyInit,
                salt: this.salt0,
            },
            messageKey,
            neededBytes,
        );
        let encryptKey = new ArrayBuffer(32);
        let authKey = new ArrayBuffer(32);
        let iv = new ArrayBuffer(16);

        for (let i = 0; i < neededBytes; i++)
        {
            if (i < 32)
                encryptKey[i] = key_init[i];
            else if (i < 64)
                authKey[i] = key_init[i];
            else
                iv[i] = key_init[i];
        }
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
            {name: 'HMAC', hash: 'SHA-256'},
            false,
            ['sign', 'verify']
        );
        return {encryptKey, iv, authKey}
    }

    async computeChainKey()
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

    async kdfCK(inputKey)
    {
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
        
        let messageKey = await this.convertToHKDF(await subtle.sign
            (
                {name: 'HMAC'},
                inputKey,
                msgKeyInput,
            )
        );

        return {chainKey, messageKey}
    }

    encodeHeader(header)
    {
        return (new TextEncoder).encode(JSON.stringify(header));
    }

    async decryptMsg(messageKey, cipherText, header, hashHeader)
    {
        const {iv, encryptKey, authKey} = await this.generateEncryptKeys(messageKey);
        this.n_r += 1;
        const verified = await subtle.verify(
            {name: 'HMAC'},
            authKey,
            hashHeader,
            this.encodeHeader(header)
        ) 
        if (!verified)
            throw `Message Integrity Error; Message No: ${this.n_r}`;

        const plainBytes = await subtle.decrypt(
            {name: 'AES-CBC', iv},
            encryptKey,
            cipherText
        );
        return (new TextDecoder).decode(plainBytes);
    }

    async ratchetEncrypt(plaintext)
    {
        const {chainKey, messageKey} = await this.kdfCK(this.chainKeyS);
        this.chainKeyS = chainKey;

        let header = {
            publicKey: this.dhsKeys.publicKey,
            p_n: this.p_n,
            n: this.n_s,
        };
        this.n_s++;
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

        const hashHeader = await subtle.sign({name: 'HMAC'}, authKey, this.encodeHeader(header));

        return {header, cipherText, hashHeader};
    }

    async ratchetDecrypt(header, cipherText, hashHeader)
    {
        const plainTextBytes = await this.trySkippedMessageKeys(header, cipherText, hashHeader);
        if (plainTextBytes)
            return (new TextDecoder).decode(plainTextBytes);
        if (!this.dhrPK || header.publicKey != this.dhrPK)
        {
            await this.skipMessageKeys(header.p_n);
            await this.setUpDHRatchet(header);
        }
        await this.skipMessageKeys(header.n_s);
        const {chainKey, messageKey} = await this.kdfCK(this.chainKeyR);
        this.chainKeyR = chainKey
        return this.decryptMsg(messageKey, cipherText, header, hashHeader);
    }

    async trySkippedMessageKeys(header, cipherText, hashHeader)
    {
        let index = this.msSkip.findIndex(i => i.publicKey == header.publicKey && i.n_s == header.n_r);
        if (index > 0)
        {
            const messageKey = this.msSkip[i].msgKey;
            this.msSkip.splice(index, 1);
            return decryptMsg(messageKey, cipherText, header, hashHeader);
        }
        return null;
    }

    async skipMessageKeys(p_n)
    {
        if (this.chainKeyR != null)
        {
            while (this.n_r < p_n)
            {
                const {chainKeyS, messageKey} = this.kdfCK(this.chainKeyR);
                this.chainKeyS = chainKeyS;
                this.msSkip.push({publicKey: this.dhrPK, msgKey: messageKey, n: this.n_r});
                this.n_r++;
            }
        }
    }

    async setUpDHRatchet(header)
    {
        this.p_n = header.n;
        this.n_s = 0;
        this.n_r = 0;
        this.dhrPK = header.publicKey;
        let keyPair = await this.computeChainKey();
        this.rootKey = keyPair.rootKey;
        this.chainKeyR = keyPair.chainKey;
        await this.generateDH();
        keyPair = await this.computeChainKey();
        this.rootKey = keyPair.rootKey;
        this.chainKeyS = keyPair.chainKey;
    }
}

const main = async () => {
    let a = new Messenger();
    let b = new Messenger();
    await a.generateDH();
    await b.generateDH();
    let apkr = a.getDHPublicKey();
    let bpkr = b.getDHPublicKey();
    await a.generateRootKey(bpkr);
    await b.generateRootKey(apkr);

    await a.generateDH();
    await b.generateDH();
    bpkr = b.getDHPublicKey();
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
};

main();

