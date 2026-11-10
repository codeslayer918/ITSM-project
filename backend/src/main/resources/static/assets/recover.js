"use strict";

let magicToken = "";

// Reads the magic-link token from the URL fragment. Also runs on "hashchange": pasting the link in a
// tab that already shows this page only changes the fragment and does not reload the page.
function applyMagicToken() {
  const token = tokenFromFragment();
  if (!token) return;
  magicToken = token;
  document.getElementById("request-link-box").hidden = true;
  document.getElementById("complete-link-box").hidden = false;
}
applyMagicToken();
window.addEventListener("hashchange", applyMagicToken);

function csrFields() {
  return { csr: document.getElementById("csr").value, label: document.getElementById("label").value };
}

document.getElementById("recover-code").addEventListener("click", async () => {
  try {
    const result = await api("POST", "/api/recovery/backup-code", Object.assign(csrFields(), {
      username: document.getElementById("username").value.trim(),
      backupCode: document.getElementById("code").value.trim()
    }));
    showMessage("msg-code", result.message, true);
    renderIssued("issued", result);
  } catch (e) {
    showMessage("msg-code", e.message, false);
  }
});

document.getElementById("request-link").addEventListener("click", async () => {
  try {
    const result = await api("POST", "/api/recovery/magic-link", { email: document.getElementById("email").value.trim() });
    showMessage("msg-link", result.message, true);
  } catch (e) {
    showMessage("msg-link", e.message, false);
  }
});

document.getElementById("complete-link").addEventListener("click", async () => {
  try {
    const result = await api("POST", "/api/recovery/magic-link/complete", Object.assign(csrFields(), { token: magicToken }));
    showMessage("msg-link", result.message, true);
    renderIssued("issued", result);
  } catch (e) {
    showMessage("msg-link", e.message, false);
  }
});
