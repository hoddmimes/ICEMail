function validateEmail(email)
{
    var re = /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/;
    return re.test(email);
}

function isEmpty(x)
{
   return (
        (typeof x == 'undefined')
                    ||
        (x == null)
                    ||
        (x == false)  //same as: !x
                    ||
        (x.length == 0)
                    ||
        (x == "")
                    ||
        ('"+x+"'.replace(/\s/g,"") == "")
                    ||
        (!/[^\s]/.test(x))
                    ||
        (/^\s*$/.test(x))
  );
}

function isNumeric( pStr ) {
	var isNumericTxt = /^[-+]?(\d+|\d+\.\d*|\d*\.\d+)$/;
	return isNumericTxt.test( pStr );
}

function utf8Encode(s) {
  return unescape(encodeURIComponent(s));
}

function stringToUint8Array(str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}



function uint8ArrayToBase64(uint8Array) {
    const binaryString = String.fromCharCode.apply(null, uint8Array);
    return btoa(binaryString);
}

function base64ToUint8Array(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function utf8Decode(s) {
  return decodeURIComponent(escape(s));
}

function getTimeString() {
    const now = new Date();

    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');

    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const milliseconds = String(now.getMilliseconds()).padStart(3, '0');

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${milliseconds}`;
}



async function callServer(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                "Content-Type": "application/json",
                ...options.headers
            },
            ...options
        });

        if (!response.ok) {
            if (response.status === 401) {
                window.location.href = '/login.html';
                return null;
            }
            await handleError(response);
            return null;
        }

        const result = await response.json();

        if (!result.success) {
            await handleError(result);
            return null;
        }

        return result; // json object success,message,data

    } catch (err) {
        handleError(err);
        return null;
    }
}

async function PBKDF2( username, password ) {
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );



    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: encoder.encode(username.toLowerCase()),
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        32 * 8 // Convert bytes to bits
    );

    return Array.from(new Uint8Array(derivedBits)).map(b => ('00' + b.toString(16)).slice(-2)).join('');
}


async function sha256hash(str) {
    // Encode the string as a Uint8Array
    const encoder = new TextEncoder();
    const data = encoder.encode(str);

    // Hash the data using SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Convert the hash buffer to a hexadecimal string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return hashHex; // 256-bit hash as a hex string
}

async function hashPassword( username, password ) {
      return PBKDF2( username.toLowerCase(), password);
}


function loadPage( urlPage ) {
        window.location.href = urlPage;
}




// =================================================
// General Error Handling Functions
// =================================================

function displayError(status, message) {
    const stsMsg = document.getElementById("StatusMessage");

    if (stsMsg && stsMsg.tagName === "DIV") {
        stsMsg.textContent = `${status} : ${message}`;
        stsMsg.className = "statusMessage error";
    } else {
        alert(`${status}\n\n${message}`);
    }
}


async function handleError(err) {
    let status = "Error";
    let message = "Unknown error";

    // Case 1: Fetch Response
    if (err instanceof Response) {
        status = `${err.status} ${err.statusText}`;

        try {
            const contentType = err.headers.get("content-type");

            if (contentType && contentType.includes("application/json")) {
                const body = await err.json();
                message = body?.message || body?.msgtxt || JSON.stringify(body);
            } else {
                const text = await err.text();
                try {
                    const body = JSON.parse(text);
                    message = body?.message || body?.msgtxt || text;
                } catch {
                    message = text;
                }
            }
        } catch {
            message = "Failed to read error response";
        }
    }

    // Case 2: Application-level JSON error
    else if (typeof err === "object" && err?.msgtxt) {
        message = err.msgtxt;
    }

    // Case 3: JavaScript exception
    else if (err instanceof Error) {
        message = err.message;
    }

    displayError(status, message);
}




