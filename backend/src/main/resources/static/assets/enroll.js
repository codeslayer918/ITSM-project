"use strict";

// Fills the invitation token from the URL fragment, on load and when only the fragment changes
// (link pasted in a tab that already shows this page).
function applyEnrollmentToken() {
  const token = tokenFromFragment();
  if (token) document.getElementById("token").value = token;
}
applyEnrollmentToken();
window.addEventListener("hashchange", applyEnrollmentToken);

document.getElementById("submit").addEventListener("click", async () => {
  try {
    const result = await api("POST", "/api/enroll", {
      token: document.getElementById("token").value.trim(),
      csr: document.getElementById("csr").value,
      label: document.getElementById("label").value
    });
    showMessage("msg", result.message, true);
    renderIssued("issued", result);
  } catch (e) {
    showMessage("msg", e.message, false);
  }
});
