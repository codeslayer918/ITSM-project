"use strict";

document.getElementById("login").addEventListener("click", async () => {
  try {
    const result = await api("POST", "/api/login");
    window.location.href = result.admin ? "/admin.html" : "/dashboard.html";
  } catch (e) {
    showMessage("msg", e.message, false);
  }
});
