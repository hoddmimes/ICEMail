// Load default content on page load
document.addEventListener("DOMContentLoaded", () => {
    create_account_init();
});

function validateUsername(username) {
    const pattern = /^[a-zA-Z][a-zA-Z0-9_]{2,31}$/;
    return pattern.test(username);
}

function create_account_init() {
    const btn = document.getElementById("submit");
    const stsmsg = document.getElementById("StatusMessage");

      btn.addEventListener("click", async () => {
      stsmsg.textContent = "";
      stsmsg.className = "";


      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;
      const password2 = document.getElementById("password2").value;
      const confMail = document.getElementById("confMail").value;


      if (isEmpty(username) || isEmpty(password)) {
        stsmsg.textContent = "Username and password required";
        stsmsg.className = "error";
        return;
      }

      if ((username.length < 3) || (username > 32)){
         stsmsg.textContent = "Username must be between 3 and 32 character";
         stsmsg.className = "error";
         return;
      }

      if (!validateUsername( username )) {
        stsmsg.textContent = "Invalid characters in username";
        stsmsg.className = "error";
        return;
      }

      if (password !== password2) {
        stsmsg.textContent = "Passwords do not match";
        stsmsg.className = "error";
        return;
      }

      if ((password.length < 8) || (password.length > 32)) {
         stsmsg.textContent = "Passwords must be between 8 to 32 characters";
         stsmsg.className = "error";
         return;
      }

      if (!validateEmail(confMail)) {
               stsmsg.textContent = "Invalid confirmation mail address";
               stsmsg.className = "error";
               return;
      }

      const altchaWidget = document.getElementById("altcha");
      const altchaPayload = altchaWidget?.querySelector('input[type="hidden"]')?.value || altchaWidget?.value || null;
      if (!altchaPayload) {
        stsmsg.textContent = "Please complete the CAPTCHA";
        stsmsg.className = "error";
        return;
      }

      btn.disabled = true;

      try {

        const hPassword = await hashPassword( username, password );

        const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
            type: 'ecc', // Type of the key, defaults to ECC
            curve: 'curve25519', // ECC curve name, defaults to curve25519
            userIDs: [{ name: username, email: username + '@icemail.com' }], // you can pass multiple user IDs
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


        jRequest = {'username' : username.toLowerCase(),
                    'password' : hPassword,
                    'privateKey' : encB64PrivateKey,
                    'publicKey' : publicKey,
                    'lastSeen' : datestr,
                    'confMail' : confMail,
                    'confirmed' : false,
                    'altcha' : altchaPayload };

        const jResponse = await callServer("/register", {
          method: "POST",
          body: JSON.stringify( jRequest )
        });

        if (!jResponse) {
            console.log("no data");
            return;
        } else {
            const stsMsg = document.getElementById("StatusMessage");

            if (stsMsg && stsMsg.tagName === "DIV") {
                stsMsg.textContent = `${jResponse.message}`;
                stsMsg.className = "statusMessage success";
                document.getElementById("username").value = "";
                document.getElementById("password").value = "";
                document.getElementById("password2").value = "";
                document.getElementById("confMail").value = "";
                if (altchaWidget) altchaWidget.reset();
            }
        }



      } catch (e) {
        stsmsg.textContent = "Error creating account, reason: " + e.message;
        stsmsg.className = "error";
      } finally {
        btn.disabled = false;
      }
    });
 }
