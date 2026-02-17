// Disable right click
document.addEventListener("contextmenu", function (e) {
  e.preventDefault();
});

// Basic devtools blockers (tidak 100% tapi bikin repot dikit)
document.addEventListener("keydown", function (e) {
  if (e.key === "F12") {
    e.preventDefault();
  }
  if (e.ctrlKey && e.shiftKey && ["I", "J", "C"].includes(e.key.toUpperCase())) {
    e.preventDefault();
  }
  if (e.ctrlKey && e.key.toUpperCase() === "U") {
    e.preventDefault();
  }
});

// Copy buttons
document.addEventListener("click", function (e) {
  const btn = e.target.closest(".btn-copy");
  if (!btn) return;

  const value = btn.getAttribute("data-copy");
  if (!value) return;

  navigator.clipboard
    .writeText(value)
    .then(() => {
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = "Copy"), 1500);
    })
    .catch(() => {});
});