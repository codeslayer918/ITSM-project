"use strict";

async function loadProfile() {
  const me = await api("GET", "/api/me");
  const a = me.account;
  document.getElementById("profile").replaceChildren(
    el("tr", {}, el("th", {}, "User"), el("td", {}, a.username + " <" + a.email + ">")),
    el("tr", {}, el("th", {}, "Group / role"), el("td", {}, a.group + " / " + a.role)),
    el("tr", {}, el("th", {}, "Certificate used"), el("td", {}, el("code", {}, me.currentCertificateSubject),
      " serial ", el("code", {}, me.currentCertificateSerial))),
    el("tr", {}, el("th", {}, "Session started"), el("td", {}, formatDate(me.sessionStartedAt)))
  );
  document.getElementById("codes-left").textContent = a.backupCodesRemaining;
  document.getElementById("admin-link").hidden = !me.adminSession;
}

async function loadCertificates() {
  const certs = await api("GET", "/api/me/certificates");
  document.getElementById("certs").replaceChildren(...certs.map((c) => el("tr", {},
    el("td", {}, c.label, c.current ? " (this device)" : ""),
    el("td", {}, el("code", {}, c.serial)),
    el("td", {}, badge(c.status), c.revocationReason ? " " + c.revocationReason : ""),
    el("td", {}, c.issuedVia),
    el("td", {}, formatDate(c.notAfter)),
    el("td", {}, c.status === "ACTIVE" ? el("button", {
      class: "small danger",
      onclick: async () => {
        try {
          await api("POST", "/api/me/certificates/" + c.serial + "/revoke");
          showMessage("msg", "Certificate " + c.serial + " revoked.", true);
          if (c.current) { window.location.href = "/"; return; }
          await refresh();
        } catch (e) { showMessage("msg", e.message, false); }
      }
    }, "Revoke") : null)
  )));
}

async function refresh() {
  try {
    await loadProfile();
    await loadCertificates();
  } catch (e) {
    if (e.status === 401 || e.status === 403) { window.location.href = "/"; return; }
    showMessage("msg", e.message, false);
  }
}

document.getElementById("add-device").addEventListener("click", async () => {
  try {
    const result = await api("POST", "/api/me/certificates", {
      csr: document.getElementById("device-csr").value,
      label: document.getElementById("device-label").value
    });
    renderIssued("issued", result);
    showMessage("msg", result.message, true);
    await refresh();
  } catch (e) { showMessage("msg", e.message, false); }
});

document.getElementById("regen-codes").addEventListener("click", async () => {
  try {
    const result = await api("POST", "/api/me/backup-codes");
    const pre = document.getElementById("codes");
    pre.textContent = result.backupCodes.join("\n");
    pre.hidden = false;
    showMessage("msg", result.message, true);
    await loadProfile();
  } catch (e) { showMessage("msg", e.message, false); }
});

document.getElementById("logout").addEventListener("click", async (event) => {
  event.preventDefault();
  try { await api("POST", "/api/logout"); } catch (e) { /* already logged out */ }
  window.location.href = "/";
});

refresh();
