/* main.js - page switching and start-up. */
"use strict";

(() => {
  const started = {};

  function homeDiagram() {
    const d = $("#home-rounds");
    if (!d || d.childElementCount) return;
    const tag = (cls, t) => el("span", { class: `op-tag ${cls}` }, t);
    const arrow = () => el("span", { class: "arrow" }, "→");
    d.append(
      el("span", { class: "box" }, "plaintext"), arrow(), tag("op-ark", "AddRoundKey"), arrow(),
      el("span", { class: "loop", "data-label": "rounds 1–9" }, tag("op-sub", "SubBytes"), tag("op-shift", "ShiftRows"), tag("op-mix", "MixColumns"), tag("op-ark", "AddRoundKey")),
      arrow(),
      el("span", { class: "loop", "data-label": "round 10" }, tag("op-sub", "SubBytes"), tag("op-shift", "ShiftRows"), tag("op-ark", "AddRoundKey")),
      arrow(), el("span", { class: "box" }, "ciphertext"));
  }

  function show() {
    const page = (location.hash || "#home").slice(1);
    const known = ["home", "aes", "keys", "modes", "lab"];
    const p = known.includes(page) ? page : "home";
    $$(".page").forEach((s) => s.classList.toggle("active", s.id === `page-${p}`));
    $$(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === p));
    syncKeyInputs();
    if (!started[p] && App.pages[p] && App.pages[p].run) { started[p] = true; App.pages[p].run(); }
    window.scrollTo({ top: 0 });
  }

  document.addEventListener("DOMContentLoaded", () => {
    Object.values(App.pages).forEach((pg) => pg.init && pg.init());
    homeDiagram();
    window.addEventListener("hashchange", show);
    show();
    api("/api/version").then((v) => { $("#version").textContent = `· aesmodes v${v.version}`; }).catch(() => {});
  });
})();
