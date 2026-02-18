// public/js/protect.js

// Disable right-click
document.addEventListener("contextmenu", function (e) {
  e.preventDefault();
});

// Basic key blocking (F12, Ctrl+Shift+I/J/C, Ctrl+U)
document.addEventListener("keydown", function (e) {
  const key = e.key || "";
  const code = e.keyCode || e.which;

  // F12
  if (code === 123) {
    e.preventDefault();
    e.stopPropagation();
  }

  // Ctrl+Shift+I / J / C
  if (e.ctrlKey && e.shiftKey && ["I", "J", "C"].includes(key.toUpperCase())) {
    e.preventDefault();
    e.stopPropagation();
  }

  // Ctrl+U
  if (e.ctrlKey && key.toUpperCase() === "U") {
    e.preventDefault();
    e.stopPropagation();
  }
});
