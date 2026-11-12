/* common.js - helpers shared by every page.
   All cryptography happens on the Python side (aesmodes/); this file only
   talks to the server and draws things. */
"use strict";

const App = {
  pages: {},
  state: {
    key: localStorage.getItem("aes.key") || "2b7e151628aed2a6abf7158809cf4f3c",
  },
  setKey(k) {
    this.state.key = k.trim();
    try { localStorage.setItem("aes.key", this.state.key); } catch (e) { /* storage unavailable */ }
  },
};

/* ------------------------------------------------------------ server calls */
async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  const res = await fetch(path, opts);
  let data;
  try { data = await res.json(); } catch (e) { throw new Error("The server returned an invalid response."); }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status}).`);
  return data;
}

/* ------------------------------------------------------------ DOM helpers */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k === "style" && typeof v === "object") Object.assign(n.style, v);
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

function showError(id, err) {
  const box = document.getElementById(id);
  if (!box) return;
  if (err) { box.textContent = err.message || String(err); box.hidden = false; }
  else box.hidden = true;
}

/* segmented control: returns getter, calls onChange(value) */
function segmented(id, onChange) {
  const root = document.getElementById(id);
  root.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    $$("button", root).forEach((x) => x.classList.toggle("on", x === b));
    onChange && onChange(b.dataset.v);
  });
  return {
    get: () => $("button.on", root).dataset.v,
    set: (v) => $$("button", root).forEach((x) => x.classList.toggle("on", x.dataset.v === v)),
  };
}

/* ------------------------------------------------------------ math */
function tex(src, display = false) {
  const span = el("span");
  if (window.katex) {
    katex.render(src, span, { displayMode: display, throwOnError: false });
  } else {
    span.textContent = src;
  }
  return span;
}
function texHTML(src, display = false) {
  return window.katex ? katex.renderToString(src, { displayMode: display, throwOnError: false }) : src;
}

/* ------------------------------------------------------------ bytes */
const hexBytes = (h) => (h.match(/../g) || []);
const shortHex = (h) => (h.length > 16 ? h.slice(0, 8) + "…" + h.slice(-8) : h);
const groupHex = (h) => hexBytes(h).join(" ");
const toBin = (b) => parseInt(b, 16).toString(2).padStart(8, "0");

/* pastel color for a byte value: the hue follows the value, so equal bytes share a color */
function byteColor(b) {
  const v = typeof b === "string" ? parseInt(b, 16) : b;
  const hue = Math.round((v * 360) / 256 + 200) % 360;
  return { bg: `hsl(${hue} 62% 89%)`, fg: `hsl(${hue} 45% 28%)` };
}

/* 4x4 state matrix (list of rows of hex strings) */
function matrix(m, opts = {}) {
  const box = el("div", { class: "matrix" + (opts.size ? " " + opts.size : "") });
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      const v = m[r][c];
      const col = byteColor(v);
      const cell = el("div", {
        class: "cell" + (opts.onClick ? " clickable" : ""),
        style: { background: col.bg, color: col.fg },
        title: opts.size === "tiny" ? undefined : `row ${r}, column ${c}: 0x${v}`,
      }, opts.size === "tiny" ? "" : v);
      cell.dataset.r = r; cell.dataset.c = c;
      if (opts.sel && opts.sel[0] === r && opts.sel[1] === c) cell.classList.add("sel");
      if (opts.col !== undefined && opts.col !== c) cell.classList.add("dim");
      if (opts.onClick) cell.addEventListener("click", () => opts.onClick(r, c));
      if (opts.onHover) cell.addEventListener("mouseenter", () => opts.onHover(r, c));
      box.append(cell);
    }
  }
  if (!opts.label) return box;
  return el("div", { class: "mat-wrap" }, el("div", { class: "mat-label", html: opts.label }), box);
}

function opArrow(label) {
  return el("div", { class: "op-arrow" }, el("span", { class: "ar" }, "→"), el("span", { html: label || "" }));
}

/* parse a counter / hex convenience */
function cleanHex(s) { return (s || "").replace(/\s+/g, "").replace(/^0x/i, "").toLowerCase(); }

/* key inputs on every page stay in sync */
function bindKeyInput(input) {
  input.value = App.state.key;
  input.addEventListener("change", () => App.setKey(input.value));
  App.keyInputs = (App.keyInputs || []).concat(input);
}
function syncKeyInputs() {
  (App.keyInputs || []).forEach((i) => { if (document.activeElement !== i) i.value = App.state.key; });
}
