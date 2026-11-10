"use strict";

async function action(fn, successText) {
  try {
    const result = await fn();
    showMessage("msg", successText(result), true);
    await refresh();
    return result;
  } catch (e) {
    showMessage("msg", e.message, false);
    return null;
  }
}

function showInvite(result) {
  const pre = document.getElementById("invite");
  pre.textContent = "Enrolment token for " + result.username + " (valid until " + formatDate(result.expiresAt) + "):\n"
    + result.enrollmentToken + "\n\nLink: " + result.enrollmentUrl
    + "\n\nCLI: ./scripts/enroll.sh --token " + result.enrollmentToken + " --out clients/" + result.username;
  pre.hidden = false;
}

async function loadUsers() {
  const users = await api("GET", "/api/admin/users");
  document.getElementById("users").replaceChildren(...users.map((u) => el("tr", {},
    el("td", {}, u.username), el("td", {}, u.email), el("td", {}, u.group), el("td", {}, u.role),
    el("td", {}, badge(u.status)), el("td", {}, u.activeCertificates), el("td", {}, u.backupCodesRemaining),
    el("td", {},
      el("button", { class: "small danger", onclick: () => action(
        () => api("POST", "/api/admin/users/" + u.username + "/revoke", { reason: "KEY_COMPROMISE", disableAccount: false }),
        (r) => r.revokedCertificates + " certificate(s) of " + u.username + " revoked.") }, "Revoke certs"),
      " ",
      u.status === "ACTIVE"
        ? el("button", { class: "small danger", onclick: () => action(
          () => api("POST", "/api/admin/users/" + u.username + "/revoke", { reason: "AFFILIATION_CHANGED", disableAccount: true }),
          () => u.username + " revoked and disabled.") }, "Revoke + disable")
        : el("button", { class: "small", onclick: async () => {
          const r = await action(() => api("POST", "/api/admin/users/" + u.username + "/enable"),
            () => u.username + " enabled, new invitation created.");
          if (r) showInvite(r);
        } }, "Enable"),
      " ",
      u.status === "ACTIVE" ? el("button", { class: "small", onclick: async () => {
        const r = await action(() => api("POST", "/api/admin/users/" + u.username + "/enrollment-token"),
          () => "New invitation for " + u.username + ".");
        if (r) showInvite(r);
      } }, "Invite") : null)
  )));
}

async function loadGroups() {
  const groups = await api("GET", "/api/admin/groups");
  const select = document.getElementById("group-name");
  const previous = select.value;
  select.replaceChildren(...Object.entries(groups).map(([name, count]) =>
    el("option", { value: name }, name + " (" + count + " active)")));
  if (previous) select.value = previous;
}

async function loadCertificates() {
  const certs = await api("GET", "/api/admin/certificates");
  document.getElementById("certs").replaceChildren(...certs.map((c) => el("tr", {},
    el("td", {}, c.username), el("td", {}, c.group), el("td", {}, c.label), el("td", {}, el("code", {}, c.serial)),
    el("td", {}, badge(c.status), c.revocationReason ? " " + c.revocationReason : ""),
    el("td", {}, c.issuedVia), el("td", {}, formatDate(c.notAfter)),
    el("td", {}, c.status === "ACTIVE" ? el("button", { class: "small danger", onclick: () => action(
      () => api("POST", "/api/admin/certificates/" + c.serial + "/revoke", { reason: "KEY_COMPROMISE" }),
      () => "Certificate " + c.serial + " revoked.") }, "Revoke") : null)
  )));
}

async function loadAudit() {
  const events = await api("GET", "/api/admin/audit");
  document.getElementById("audit").replaceChildren(...events.map((e) => el("tr", {},
    el("td", {}, formatDate(e.occurredAt)), el("td", {}, e.eventType), el("td", {}, e.outcome),
    el("td", {}, e.username || "-"), el("td", {}, e.sourceIp || "-"), el("td", {}, e.certSerial || "-"),
    el("td", {}, e.details || "")
  )));
}

async function refresh() {
  try {
    await Promise.all([loadUsers(), loadGroups(), loadCertificates(), loadAudit()]);
  } catch (e) {
    if (e.status === 401) { window.location.href = "/"; return; }
    showMessage("msg", e.message, false);
  }
}

document.getElementById("create-user").addEventListener("click", async () => {
  const result = await action(() => api("POST", "/api/admin/users", {
    username: document.getElementById("new-username").value.trim(),
    email: document.getElementById("new-email").value.trim(),
    group: document.getElementById("new-group").value.trim()
  }), (r) => "User " + r.username + " created.");
  if (result) showInvite(result);
});

document.getElementById("revoke-group").addEventListener("click", () => {
  const group = document.getElementById("group-name").value;
  action(() => api("POST", "/api/admin/groups/" + encodeURIComponent(group) + "/revoke", {
    reason: document.getElementById("group-reason").value,
    disableAccount: document.getElementById("group-disable").checked
  }), (r) => "Group " + group + ": " + r.revokedCertificates + " certificate(s) revoked, "
    + r.affectedAccounts + " account(s) affected.");
});

document.getElementById("publish-crl").addEventListener("click", () =>
  action(() => api("POST", "/api/admin/crl/publish"), (r) => "CRL #" + r.crlNumber + " published."));

document.getElementById("logout").addEventListener("click", async (event) => {
  event.preventDefault();
  try { await api("POST", "/api/logout"); } catch (e) { /* ignore */ }
  window.location.href = "/";
});

refresh();
