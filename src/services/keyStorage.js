const crypto = window.crypto;
const subtle = crypto.subtle;

// Following Mozilla guide on IndexedDB https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API/Using_IndexedDB
// Salt length: 16 bytes or 128-bits https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
// Iterations for PBKDF2 with PBKDF2-HMAC-SHA256: 310,000 https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
const saltSize = 16;
const pbkdf2IterSHA256 = 310000;
const dbHashType = "hashes";
const passwordHashType = "password";

let db = null;

async function checkDBPersist()
{
    if (navigator.storage && navigator.storage.persist && !(await navigator.storage.persisted()))
        await navigator.storage.persist();
    if (db == null)
    {
        const req = window.indexedDB.open('app', 6);
        await (new Promise((resolve) =>
        {
            req.onupgradeneeded  = (event) => 
            {
                console.log('test');
                db = event.target.result;
                const objectStore = db.createObjectStore(dbHashType, {keyPath: "type"});
                objectStore.oncomplete = (e) => resolve();
            };
            req.onsuccess = (event) => 
            {
                if (db == null)
                    db = event.target.result;
                resolve();
            }
        }));
    }
}

async function passwordToPBKDF2(password, salt)
{
    const passwordKey = await subtle.importKey('raw', (new TextEncoder()).encode(password), {name: 'PBKDF2'}, false, ['deriveBits', 'deriveKey']);
    const hash = await subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: pbkdf2IterSHA256,
            hash: 'SHA-256'
        },
        passwordKey,
        256
    );
    return hash;
}

async function createPassword(password)
{
    await checkDBPersist();

    const salt = crypto.getRandomValues(new Uint8Array(saltSize));
    const hash = await passwordToPBKDF2(password, salt);
    
    
    // Create hash type in DB then add hash and salt for password when db type completed only
    await (new Promise((resolve) => 
    {
        const transaction = db.transaction(dbHashType, 'readwrite');
        const adding = transaction.objectStore(dbHashType).add({type: passwordHashType, hash: hash, salt: salt, value: null});
        adding.onsuccess = (e) => resolve();
    }));
    
}

async function checkPassword(password)
{
    const hashPair = await (new Promise((resolve) => {
        const request = db.transaction(dbHashType).objectStore(dbHashType).get(passwordHashType);
        request.onsuccess = (event) => resolve(request.result)
    }));
    console.log(hashPair);
    const hashedGivenPass = await passwordToPBKDF2(password, hashPair.salt);
    if (hashedGivenPass == hashPair.hash)
        return true;
    else
        return false;
}

async function encryptString(messengerList, , password)
{

}

function decryptString(ciphertext, password)
{

}

async function main() {
    let key = await window.crypto.subtle.generateKey(
        {
          name: "HMAC",
          hash: {name: "SHA-512"}
        },
        true,
        ["sign", "verify"]
      );
    console.log(await subtle.exportKey('raw', key));
    const password = "asdf";
    await createPassword(password);
    await checkPassword(password);
}

// main();