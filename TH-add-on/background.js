// Thunderbird can terminate idle backgrounds in Manifest V3.
// Any listener directly added during add-on startup will be registered as a
// persistent listener and the background will wake up (restart) each time the
// event is fired.

// Note: The `onBeforeSend` event could cause a long idle time, which will
//   terminate the background page and dead-lock the compose window. To mitigate
//   this limitation introduced in Manifest V3, we use the alarms API to ping
//   the background page.

let promiseMap = new Map();
browser.composeAction.disable();

// -- Keep-alive helper (prevents MV3 background termination) -----------------

async function promiseWithoutTermination(name, promise) {
  const listener = (alarmInfo) => {
    if (alarmInfo.name == name) {
      console.info(`Waiting for ${name}`);
    }
  };
  browser.alarms.create(name, { periodInMinutes: 0.25 });
  browser.alarms.onAlarm.addListener(listener);

  const rv = await promise;

  await browser.alarms.clear(name);
  browser.alarms.onAlarm.removeListener(listener);
  return rv;
}

// -- Encryption helpers ------------------------------------------------------

function arrayBufferToBase64(buffer) {
  let bytes = new Uint8Array(buffer);
  let binary = "";
  for (let b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

function generateHexUID(byteLength) {
  let bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function encryptBody(body, password) {
  let encoder = new TextEncoder();
  let salt = crypto.getRandomValues(new Uint8Array(16));
  let iv = crypto.getRandomValues(new Uint8Array(12));

  // Derive key from password using PBKDF2
  let keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  let key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  // Encrypt
  let ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(body)
  );

  // Package as JSON then base64
  let payload = JSON.stringify({
    salt: arrayBufferToBase64(salt),
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertext),
  });

  return btoa(payload);
}

function wrapEncryptedBody(base64Payload) {
  return (
    "-----BEGIN ICE ENCRYPTED MESSAGE-----\n" +
    base64Payload +
    "\n-----END ICE ENCRYPTED MESSAGE-----"
  );
}

// -- onBeforeSend handler ----------------------------------------------------

browser.compose.onBeforeSend.addListener(async (tab) => {
  await browser.composeAction.enable(tab.id);
  await browser.composeAction.openPopup();

  let { promise, resolve } = Promise.withResolvers();
  promiseMap.set(tab.id, resolve);
  return promiseWithoutTermination("onBeforeSend", promise);
});

// -- Message handler (from popup) --------------------------------------------

browser.runtime.onMessage.addListener(async (message) => {
  let resolve = promiseMap.get(message.tabId);
  if (!resolve) {
    return;
  }
  promiseMap.delete(message.tabId);
  browser.composeAction.disable(message.tabId);

  if (message.action === "skip") {
    resolve();
    return;
  }

  if (message.action === "encrypt") {
    try {
      // Read the current compose details.
      let details = await browser.compose.getComposeDetails(message.tabId);
      let isPlainText = details.isPlainText;

      // Get the body content to encrypt. Use plainTextBody for plain text
      // compose, body (HTML) for HTML compose.
      let bodyContent = isPlainText
        ? (details.plainTextBody || "")
        : (details.body || "");

      // Encrypt the body.
      let encrypted = await encryptBody(bodyContent, message.password);
      let wrappedBody = wrapEncryptedBody(encrypted);

      // Generate a random ICE-UID (16 bytes = 32 hex chars).
      let iceUID = generateHexUID(16);

      // Update the compose details with the encrypted body and custom header
      // using setComposeDetails() directly, then resolve to allow the send.
      let newDetails = {
        customHeaders: [{ name: "X-ICE-UID", value: iceUID }],
      };
      if (isPlainText) {
        newDetails.plainTextBody = wrappedBody;
      } else {
        newDetails.body = `<pre>${wrappedBody}</pre>`;
      }
      await browser.compose.setComposeDetails(message.tabId, newDetails);

      resolve();
    } catch (e) {
      console.error("ICE Encryption failed:", e);
      // On error, cancel the send so the user doesn't send unencrypted.
      resolve({ cancel: true });
    }
  }
});
