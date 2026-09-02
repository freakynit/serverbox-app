/* Serverbox site — small progressive enhancement script.
   Handles: scroll reveals, FAQ accordion, mobile nav toggle.
   Everything degrades gracefully if JS is disabled. */
(function () {
  "use strict";
  var doc = document.documentElement;
  doc.classList.add("js");

  // ---- Mobile nav ----
  var btn = document.querySelector("[data-menu-toggle]");
  var panel = document.querySelector("[data-menu-panel]");
  if (btn && panel) {
    btn.addEventListener("click", function () {
      var open = panel.classList.toggle("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // ---- FAQ accordion ----
  document.querySelectorAll(".faq-item").forEach(function (item) {
    var q = item.querySelector(".faq-q");
    if (!q) return;
    q.addEventListener("click", function () {
      var isOpen = item.classList.contains("open");
      // close siblings within the same faq list
      var list = item.closest(".faq");
      if (list) list.querySelectorAll(".faq-item.open").forEach(function (o) {
        if (o !== item) { o.classList.remove("open"); o.querySelector(".faq-q").setAttribute("aria-expanded", "false"); }
      });
      item.classList.toggle("open", !isOpen);
      q.setAttribute("aria-expanded", isOpen ? "false" : "true");
    });
  });

  // ---- Scroll reveal ----
  var reveals = document.querySelectorAll(".reveal");
  if (!("IntersectionObserver" in window) || reveals.length === 0) {
    reveals.forEach(function (el) { el.classList.add("in"); });
    return;
  }
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) {
        e.target.classList.add("in");
        io.unobserve(e.target);
      }
    });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  reveals.forEach(function (el) { io.observe(el); });

  // safety net: reveal everything shortly after load in case observer misbehaves
  setTimeout(function () {
    reveals.forEach(function (el) { el.classList.add("in"); });
  }, 1800);
})();
