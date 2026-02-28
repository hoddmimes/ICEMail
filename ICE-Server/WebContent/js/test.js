async function testKeysII() {
    const password = document.getElementById("Password").value;
    const username = document.getElementById("Username").value;

    const hexStr = await PBKDF2(username, password)
    const result = document.getElementById("Result");
    result.textContent = "PBKDF2: " + hexStr;
    console.log(  "PBKDF2: " + hexStr );
}


async function testKeys() {

    const username = 'lucas';
    const password = document.getElementById("Password").value;
    const confMail = 'lucas@foobar.com';

   const salt = CryptoJS.MD5(username).toString();
   console.log("Salt (hex):", salt);

           const hPassword  = await argon2.hash({
                                      pass: password,
                                      salt: salt,
                                      type: argon2.ArgonType.Argon2id,
                                      time: 3,          // iterations
                                      mem: 65536,       // memory in KiB (64 MB)
                                      parallelism: 1,
                                      hashLen: 32       // output length in bytes
                                    });

           const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
               type: 'ecc', // Type of the key, defaults to ECC
               curve: 'curve25519', // ECC curve name, defaults to curve25519
               userIDs: [{ name: username, email: username + '@example.com' }], // you can pass multiple user IDs
               passphrase: password, // protects the private key
               format: 'armored' // output key format, defaults to 'armored' (other options: 'binary' or 'object')
           });


        const datestr = getTimeString();
        const privateKeyUInt8 = stringToUint8Array(privateKey);

        const privateKeyMessage = await openpgp.createMessage({ binary: privateKeyUInt8 });
        const encPrivateKey = await openpgp.encrypt({
            message: privateKeyMessage,      // Correct parameter name
            passwords: [password],            // Array of passwords
            format: 'binary'
        });

        const encB64PrivateKey = uint8ArrayToBase64( encPrivateKey );


        jbody = {'username' : username,
                 'password' : hPassword.hashHex,
                 'privatekey' : encB64PrivateKey,
                 'publickey' : publicKey,
                 'lastseen' : datestr,
                 'confirmationMail' : confMail,
                 'confirmed' : false };


        console.log( JSON.stringify( jbody ));


        //console.log(privateKey);     // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
        //console.log(publicKey);      // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
        //console.log(revocationCertificate); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
}

document.addEventListener("DOMContentLoaded", () => {
    test_init();
});

function test_init() {
    const btn = document.getElementById("submit");
    btn.addEventListener("click", testKeysII );
}





