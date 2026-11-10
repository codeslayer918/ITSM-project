// Small helpers shared by every page. No innerHTML with server data: only textContent.
"use strict";

async function api(method, url, body) {
  const options = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body || {});
  }
  const response = await fetch(url, options);
  let data = null;
  try {
    data = await response.json();
  } catch (e) {
    data = null;
  }
  if (!response.ok) {
    const message = (data && (data.message || data.reason || data.error)) || ("HTTP " + response.status);
    const error = new Error(message);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([key, value]) => {
    if (key === "onclick") node.addEventListener("click", value);
    else if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  });
  children.flat().forEach((child) => {
    if (child === null || child === undefined) return;
    node.appendChild(typeof child === "string" || typeof child === "number" || typeof child === "boolean"
      ? document.createTextNode(String(child)) : child);
  });
  return node;
}

function showMessage(id, text, ok) {
  const node = document.getElementById(id);
  node.textContent = text;
  node.className = "msg " + (ok ? "ok" : "err");
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

function badge(status) {
  return el("span", { class: "badge " + status }, status);
}

function downloadText(filename, text) {
  const link = el("a", { href: URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" })), download: filename });
  document.body.appendChild(link);
  link.click();
  link.remove();
}

// Tokens travel in the URL fragment (#token=...): never sent to the server or in Referer.
function tokenFromFragment() {
  const match = /(?:^|[#&])token=([A-Za-z0-9_-]+)/.exec(window.location.hash);
  if (match) history.replaceState(null, "", window.location.pathname);
  return match ? match[1] : "";
}

// Renders the certificate returned by enrolment / recovery / add-device.
function renderIssued(containerId, result) {
  const box = document.getElementById(containerId);
  box.replaceChildren(
    el("h2", {}, "Certificate issued"),
    el("p", {}, result.message),
    el("p", {}, "Subject: ", el("code", {}, result.subject), " - serial ", el("code", {}, result.serial),
      " - expires ", formatDate(result.notAfter)),
    el("button", { onclick: () => downloadText("cert.pem", result.certificatePem) }, "Download cert.pem"),
    " ",
    el("button", { onclick: () => downloadText("chain.pem", result.chainPem) }, "Download chain.pem"),
    el("p", { class: "hint" }, "Then build the PKCS#12 next to your private key and import it in your browser:"),
    el("pre", {}, "openssl pkcs12 -export -inkey key.pem -in cert.pem -certfile chain.pem -out client.p12"),
    result.backupCodes ? el("div", {},
      el("h2", {}, "Backup codes (shown once)"),
      el("p", { class: "hint" }, "Each code works once and only to enrol a new certificate if you lose this one."),
      el("pre", {}, result.backupCodes.join("\n")),
      el("button", { onclick: () => downloadText("backup-codes.txt", result.backupCodes.join("\n") + "\n") },
        "Download backup codes")) : null
  );
  box.hidden = false;
}
