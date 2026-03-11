document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("submit").addEventListener("click", changePassword);
});

async function changePassword() {
    const stsmsg = document.getElementById("StatusMessage");
    const btn    = document.getElementById("submit");
    stsmsg.textContent = "";
    stsmsg.className   = "";

    const username        = sessionStorage.getItem("username");
    const currentPassword = document.getElementById("currentPassword").value;
    const newPassword     = document.getElementById("newPassword").value;
    const newPassword2    = document.getElementById("newPassword2").value;

    if (!username) {
        stsmsg.textContent = "Session expired — please log in again";
        stsmsg.className   = "error";
        return;
    }
    if (isEmpty(currentPassword) || isEmpty(newPassword)) {
        stsmsg.textContent = "All fields are required";
        stsmsg.className   = "error";
        return;
    }
    if (newPassword !== newPassword2) {
        stsmsg.textContent = "New passwords do not match";
        stsmsg.className   = "error";
        return;
    }
    if (newPassword.length < 8 || newPassword.length > 32) {
        stsmsg.textContent = "New password must be between 8 and 32 characters";
        stsmsg.className   = "error";
        return;
    }

    btn.disabled = true;

    try {
        // Step 1: Verify current password and retrieve the encrypted private key
        const hCurrentPassword = await hashPassword(username, currentPassword);
        const loginResp = await callServer("/login", {
            method: "POST",
            body: JSON.stringify({ username: username, password: hCurrentPassword })
        });
        if (!loginResp) {
            // callServer already displayed the error
            return;
        }
        const encB64PrivateKey = loginResp.privateKey;
        if (!encB64PrivateKey) {
            stsmsg.textContent = "Could not retrieve private key from server";
            stsmsg.className   = "error";
            return;
        }

        // Step 2: Decrypt the PGP-symmetric wrapper with the current plaintext password
        const encKeyBytes = base64ToUint8Array(encB64PrivateKey);
        const encMessage  = await openpgp.readMessage({ binaryMessage: encKeyBytes });
        const decrypted   = await openpgp.decrypt({
            message:   encMessage,
            passwords: [currentPassword],
            format:    "binary"
        });
        const armoredKeyBytes = decrypted.data;

        // Step 3: Re-encrypt the wrapper with the new plaintext password
        const reEncMessage = await openpgp.createMessage({ binary: armoredKeyBytes });
        const reEncrypted  = await openpgp.encrypt({
            message:   reEncMessage,
            passwords: [newPassword],
            format:    "binary"
        });
        const newEncB64PrivateKey = uint8ArrayToBase64(reEncrypted);

        // Step 4: Also re-protect the PGP key passphrase inside the armored key
        const armoredKey    = new TextDecoder().decode(armoredKeyBytes);
        const pgpKey        = await openpgp.readPrivateKey({ armoredKey });
        const decryptedKey  = await openpgp.decryptKey({ privateKey: pgpKey, passphrase: currentPassword });
        const reEncKey      = await openpgp.encryptKey({ privateKey: decryptedKey, passphrase: newPassword });
        const newArmoredKey = reEncKey.armor();

        // Re-encrypt the wrapper using the re-passphrase-protected armored key
        const finalMessage    = await openpgp.createMessage({ binary: stringToUint8Array(newArmoredKey) });
        const finalEncrypted  = await openpgp.encrypt({
            message:   finalMessage,
            passwords: [newPassword],
            format:    "binary"
        });
        const finalEncB64 = uint8ArrayToBase64(finalEncrypted);

        // Step 5: Hash the new password and send the update to the server
        const hNewPassword = await hashPassword(username, newPassword);
        const result = await callServer("/change_password", {
            method: "POST",
            body: JSON.stringify({ newPassword: hNewPassword, newPrivateKey: finalEncB64 })
        });
        if (!result) return;

        // Update sessionStorage so in-page decryption keeps working
        sessionStorage.setItem("password", newPassword);

        stsmsg.textContent = "Password changed successfully";
        stsmsg.className   = "success";
        document.getElementById("currentPassword").value = "";
        document.getElementById("newPassword").value     = "";
        document.getElementById("newPassword2").value    = "";

    } catch (e) {
        stsmsg.textContent = "Failed to change password: " + e.message;
        stsmsg.className   = "error";
    } finally {
        btn.disabled = false;
    }
}
