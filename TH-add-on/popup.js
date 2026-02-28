let btnEncrypt = document.getElementById("btn-encrypt");
let btnSkip = document.getElementById("btn-skip");
let passwordInput = document.getElementById("password");
let confirmInput = document.getElementById("confirm-password");
let errorDiv = document.getElementById("error");

// Keep the background alive while the popup is open (belt-and-suspenders
// alongside the alarms-based keep-alive in background.js).
let keepAliveInterval = setInterval(() => {
  browser.runtime.sendMessage({ keepAlive: true });
}, 10000);

async function getActiveTabId() {
  let tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0].id;
}

btnEncrypt.addEventListener("click", async () => {
  let password = passwordInput.value;
  let confirm = confirmInput.value;

  if (!password) {
    errorDiv.textContent = "Please enter a password.";
    return;
  }
  if (password !== confirm) {
    errorDiv.textContent = "Passwords do not match.";
    return;
  }

  let tabId = await getActiveTabId();
  await browser.runtime.sendMessage({ tabId, action: "encrypt", password });
  clearInterval(keepAliveInterval);
  window.close();
});

btnSkip.addEventListener("click", async () => {
  let tabId = await getActiveTabId();
  await browser.runtime.sendMessage({ tabId, action: "skip" });
  clearInterval(keepAliveInterval);
  window.close();
});
