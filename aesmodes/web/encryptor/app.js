/* app.js - the AES Encryptor page. All cryptography runs in worker.js (Python via Pyodide). */
"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const MAX_BYTES = 25 * 1024 * 1024;

const MODES = {
  ECB: { tag: "each block alone", note: "ECB encrypts every block separately, so identical blocks give identical ciphertext and patterns leak. Fine for learning; avoid it for real data.", warn: true },
  CBC: { tag: "chained blocks", note: "CBC XORs each block with the previous ciphertext before encrypting it." },
  CFB: { tag: "cipher feedback", note: "CFB encrypts the previous ciphertext and XORs it with your data (full-block CFB-128)." },
  OFB: { tag: "output feedback", note: "OFB builds a keystream by encrypting its own output again and again, then XORs it with your data." },
  CTR: { tag: "counter", note: "CTR encrypts a counter that goes up by one per block and XORs the result with your data." },
};

/* ------------------------------------------------------------ worker */
const worker = new Worker("worker.js");
let nextId = 1;
const pending = new Map();
let engineReady = false;

worker.onmessage = (ev) => {
  const m = ev.data;
  if (m.type === "status") $("#loading-text").textContent = m.text;
  else if (m.type === "ready") { engineReady = true; $("#loading").hidden = true; }
  else if (m.type === "fatal") { $("#loading-text").textContent = "The encryption engine could not start: " + m.message; }
  else {
    const p = pending.get(m.id);
    if (!p) return;
    if (m.type === "progress") p.onProgress && p.onProgress(m.done, m.total);
    else { pending.delete(m.id); m.type === "result" ? p.resolve(m) : p.reject(new Error(m.message)); }
  }
};

function call(cmd, opts, data, onProgress) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject, onProgress });
    worker.postMessage({ id, cmd, opts, data }, data ? [data.buffer] : []);
  });
}

/* ------------------------------------------------------------ small helpers */
function switcher(sel, onChange) {
  const root = $(sel);
  root.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    root.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
    onChange && onChange(b.dataset.v);
  });
  return () => root.querySelector("button.on").dataset.v;
}
const fmtBytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`;
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
function showErr(sel, msg) { const e = $(sel); e.textContent = msg || ""; e.hidden = !msg; }
function download(bytes, name) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
function progressUI(sel) {
  const box = $(sel), bar = box.querySelector("i"), txt = box.querySelector("span");
  return {
    start(label) { box.hidden = false; bar.style.width = "0%"; txt.textContent = label; },
    update(done, total) { const p = total ? Math.round((100 * done) / total) : 100; bar.style.width = p + "%"; txt.textContent = `${p}%`; },
    done() { box.hidden = true; },
  };
}
function setupDrop(dropSel, inputSel, labelSel, onFile) {
  const drop = $(dropSel), input = $(inputSel);
  input.addEventListener("change", () => input.files[0] && onFile(input.files[0]));
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && onFile(e.dataTransfer.files[0]));
  return (file) => { $(labelSel).innerHTML = `<b>${esc(file.name)}</b> · ${fmtBytes(file.size)}`; };
}
const readFile = (file) => file.arrayBuffer().then((b) => new Uint8Array(b));
const ivLabel = (meta) => meta.mode === "ECB" ? "none (ECB)"
  : /^0+$/.test(meta.iv) ? "0 (all zeros)" : meta.iv;
const facts = (meta, extra) => `<div class="facts">
  <div>Mode<b><span class="chip" style="background:var(--${meta.mode})">${meta.mode}</span></b></div>
  <div>Key<b>AES-${meta.keyBits} · ${esc(meta.keySource)}</b></div>
  <div>${meta.mode === "CTR" ? "Initial counter" : "IV"}<b class="mono">${esc(ivLabel(meta))}</b></div>
  ${extra || ""}<div>Time<b>${meta.seconds}s</b></div></div>`;

/* ------------------------------------------------------------ tabs */
$$(".tab").forEach((t) => t.addEventListener("click", () => {
  $$(".tab").forEach((x) => x.classList.toggle("on", x === t));
  $("#panel-enc").hidden = t.dataset.tab !== "enc";
  $("#panel-dec").hidden = t.dataset.tab !== "dec";
}));
$$(".eye").forEach((b) => b.addEventListener("click", () => {
  const i = document.getElementById(b.dataset.for);
  i.type = i.type === "password" ? "text" : "password";
}));

/* ============================================================ ENCRYPT */
let encFile = null;
let mode = "CBC";
const encKind = switcher("#enc-kind", (v) => { $("#enc-text").hidden = v !== "text"; $("#enc-drop").hidden = v !== "file"; });
const encBits = switcher("#enc-bits", () => updateHexHint());
const encKeyType = switcher("#enc-keytype", (v) => { $("#enc-pw-field").hidden = v !== "password"; $("#enc-hex-field").hidden = v !== "hex"; });
const ivKind = switcher("#enc-ivkind", () => updateIvHint());
const labelEncFile = setupDrop("#enc-drop", "#enc-file", "#enc-file-label", (f) => { encFile = f; labelEncFile(f); });

const modeBox = $("#enc-mode");
Object.entries(MODES).forEach(([m, info]) => {
  const b = document.createElement("button");
  b.className = "mode"; b.dataset.m = m; b.type = "button";
  b.innerHTML = `<b>${m}</b><span>${info.tag}</span>`;
  b.addEventListener("click", () => setMode(m));
  modeBox.append(b);
});
function setMode(m) {
  mode = m;
  $$(".mode").forEach((b) => { const on = b.dataset.m === m; b.classList.toggle("on", on); b.style.background = on ? `var(--${b.dataset.m})` : ""; });
  const note = $("#mode-note");
  note.textContent = MODES[m].note; note.classList.toggle("warn", !!MODES[m].warn);
  $("#iv-block").hidden = m === "ECB" || m === "CTR";
  $("#ctr-block").hidden = m !== "CTR";
  $("#ecb-block").hidden = m !== "ECB";
  $("#iv-title").textContent = m === "CTR" ? "Counter" : m === "ECB" ? "Initial vector" : "Initial vector (IV)";
  updateIvHint();
}
function updateIvHint() {
  $("#iv-hint").textContent = ivKind() === "zero"
    ? "As in the project specification, the IV is all zeros. Encrypting the same thing twice gives the same result, which reveals repeated messages."
    : "A fresh random IV is used and stored in the output, so the same message encrypts differently every time.";
}
function updateHexHint() {
  const bits = +encBits(), want = bits / 4, n = $("#enc-hex").value.replace(/\s/g, "").length;
  $("#enc-hex").placeholder = `${want} hex digits for AES-${bits}`;
  const h = $("#hex-hint");
  if (!n) { h.textContent = "Keep this key: you need exactly the same one to decrypt."; h.className = "hint"; return; }
  const ok = [32, 48, 64].includes(n);
  h.textContent = ok ? `${n} digits: AES-${n * 4} key (the key length sets the key size).` : `${n} digits: a key needs 32, 48 or 64 hex digits.`;
  h.className = "hint " + (ok ? "good" : "bad");
}
$("#enc-hex").addEventListener("input", updateHexHint);
$("#gen-key").addEventListener("click", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(+encBits() / 8));
  $("#enc-hex").value = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  updateHexHint();
});
$("#enc-pw").addEventListener("input", () => {
  const p = $("#enc-pw").value, h = $("#pw-strength");
  if (!p) { h.textContent = "The password is turned into a key with PBKDF2-HMAC-SHA256 (200,000 rounds, random salt)."; h.className = "hint"; return; }
  const score = (p.length >= 12) + /[a-z]/.test(p) + /[A-Z]/.test(p) + /\d/.test(p) + /[^\w]/.test(p) + (p.length >= 16);
  const [label, cls] = p.length < 8 ? ["Too short: use at least 8 characters.", "bad"] : score >= 5 ? ["Strong password.", "good"] : ["OK. Longer and more varied is stronger.", ""];
  h.textContent = label; h.className = "hint " + cls;
});

$("#enc-go").addEventListener("click", async () => {
  showErr("#enc-err"); $("#enc-result").hidden = true;
  const kind = encKind(), keyType = encKeyType();
  const opts = { mode, bits: +encBits(), keyType, password: $("#enc-pw").value, hexKey: $("#enc-hex").value,
    randomIv: mode === "CTR" ? $("#enc-ctr-rand").checked : ivKind() === "random", counter: $("#enc-ctr").value };
  if (keyType === "password" && !opts.password) return showErr("#enc-err", "Enter a password first.");
  if (keyType === "password" && opts.password.length < 4) return showErr("#enc-err", "Use a password of at least 4 characters.");
  if (keyType === "hex" && !opts.hexKey.trim()) return showErr("#enc-err", "Enter a hex key, or click Generate.");
  let data = null;
  if (kind === "text") {
    if (!$("#enc-text").value) return showErr("#enc-err", "Type a message to encrypt.");
    opts.text = $("#enc-text").value;
  } else {
    if (!encFile) return showErr("#enc-err", "Choose a file to encrypt.");
    if (encFile.size > MAX_BYTES) return showErr("#enc-err", `This file is ${fmtBytes(encFile.size)}. The limit is 25 MB.`);
    opts.name = encFile.name;
    data = await readFile(encFile);
  }
  const btn = $("#enc-go"), prog = progressUI("#enc-progress");
  btn.disabled = true; btn.textContent = engineReady ? "Encrypting…" : "Waiting for the engine…";
  prog.start(engineReady ? "Deriving key…" : "Starting…");
  try {
    const res = await call(kind === "text" ? "encryptText" : "encryptFile", opts, data, (d, t) => prog.update(d, t));
    renderEncResult(kind, res, opts);
  } catch (e) { showErr("#enc-err", e.message); }
  finally { prog.done(); btn.disabled = false; btn.textContent = "Encrypt"; }
});

function renderEncResult(kind, res, opts) {
  const box = $("#enc-result");
  if (kind === "text") {
    const token = res.meta.token;
    box.innerHTML = `<h3>✓ Message encrypted with AES-${opts.keyType === "hex" ? opts.hexKey.replace(/\s/g, "").length * 4 : opts.bits}-${mode}</h3>
      <textarea class="mono" rows="5" readonly>${esc(token)}</textarea>
      <div class="actions"><button class="btn primary" id="copy-token">Copy</button>
      <button class="btn" id="to-dec">Try decrypting it →</button></div>
      <p class="hint">Send this text to someone, together with the ${opts.keyType === "hex" ? "hex key" : "password"} (separately, by another channel).</p>`;
    $("#copy-token").onclick = (e) => { navigator.clipboard.writeText(token); e.target.textContent = "Copied ✓"; };
    $("#to-dec").onclick = () => {
      $$(".tab")[1].click(); $("#dec-kind button[data-v=text]").click();
      $("#dec-text").value = token; inspectText();
    };
  } else {
    const name = opts.name + ".aesm";
    box.innerHTML = `<h3>✓ File encrypted</h3>
      <div class="actions"><button class="btn primary" id="dl-enc">⬇ Download ${esc(name)}</button></div>
      ${facts(res.meta, `<div>Size<b>${fmtBytes(encFile.size)} → ${fmtBytes(res.meta.outBytes)}</b></div>`)}`;
    $("#dl-enc").onclick = () => download(res.data, name);
  }
  box.hidden = false;
}

/* ============================================================ DECRYPT */
let decFile = null, decInfo = null;
const decKind = switcher("#dec-kind", (v) => {
  $("#dec-text").hidden = v !== "text"; $("#dec-drop").hidden = v !== "file";
  decInfo = null; $("#dec-info").hidden = true;
  if (v === "text") inspectText(); else if (decFile) inspectFile();
});
const labelDecFile = setupDrop("#dec-drop", "#dec-file", "#dec-file-label", (f) => { decFile = f; labelDecFile(f); inspectFile(); });
let inspectTimer;
$("#dec-text").addEventListener("input", () => { clearTimeout(inspectTimer); inspectTimer = setTimeout(inspectText, 250); });

function showDetected(meta) {
  decInfo = meta;
  const needsHex = meta.keySource === "hex key";
  $("#dec-pw-field").hidden = needsHex; $("#dec-hex-field").hidden = !needsHex;
  $("#dec-info").innerHTML = `Detected: <span class="chip" style="background:var(--${meta.mode})">${meta.mode}</span>
    AES-${meta.keyBits}, ${esc(meta.keySource)}${meta.name ? `, file <b>${esc(meta.name)}</b>` : ""}, ${fmtBytes(meta.ciphertextBytes)} of ciphertext.`;
  $("#dec-info").hidden = false;
}
function clearDecrypt() { decInfo = null; $("#dec-info").hidden = true; $("#dec-result").hidden = true; showErr("#dec-err"); }
async function inspectText() {
  clearDecrypt();
  const t = $("#dec-text").value.trim();
  if (!t) { $("#dec-info").hidden = true; decInfo = null; return; }
  try { showDetected((await call("inspect", { token: t })).meta); }
  catch (e) { decInfo = null; $("#dec-info").hidden = false; $("#dec-info").textContent = e.message; }
}
async function inspectFile() {
  clearDecrypt();
  if (!decFile) return;
  try { showDetected((await call("inspect", {}, await readFile(decFile))).meta); }
  catch (e) { decInfo = null; $("#dec-info").hidden = false; $("#dec-info").textContent = e.message; }
}

$("#dec-go").addEventListener("click", async () => {
  showErr("#dec-err"); $("#dec-result").hidden = true;
  const kind = decKind();
  const keyType = decInfo && decInfo.keySource === "hex key" ? "hex" : "password";
  const opts = { keyType, password: $("#dec-pw").value, hexKey: $("#dec-hex").value };
  let data = null;
  if (kind === "text") {
    if (!$("#dec-text").value.trim()) return showErr("#dec-err", "Paste an encrypted message first.");
    opts.token = $("#dec-text").value;
  } else {
    if (!decFile) return showErr("#dec-err", "Choose an .aesm file first.");
    data = await readFile(decFile);
  }
  if (keyType === "password" && !opts.password) return showErr("#dec-err", "Enter the password.");
  if (keyType === "hex" && !opts.hexKey.trim()) return showErr("#dec-err", "Enter the hex key.");
  const btn = $("#dec-go"), prog = progressUI("#dec-progress");
  btn.disabled = true; btn.textContent = "Decrypting…"; prog.start("Checking the key…");
  try {
    const res = await call(kind === "text" ? "decryptText" : "decryptFile", opts, data, (d, t) => prog.update(d, t));
    const box = $("#dec-result"), meta = res.meta;
    if (kind === "text") {
      box.innerHTML = `<h3>✓ Decrypted · integrity check passed</h3><div class="plain">${esc(meta.text)}</div>${facts(meta)}`;
    } else {
      const name = meta.name || decFile.name.replace(/\.aesm$/i, "") || "decrypted.bin";
      box.innerHTML = `<h3>✓ File decrypted · integrity check passed</h3>
        <div class="actions"><button class="btn primary" id="dl-dec">⬇ Download ${esc(name)}</button></div>
        ${facts(meta, `<div>Size<b>${fmtBytes(meta.outBytes)}</b></div>`)}`;
      $("#dl-dec").onclick = () => download(res.data, name);
    }
    box.hidden = false;
  } catch (e) { showErr("#dec-err", e.message); }
  finally { prog.done(); btn.disabled = false; btn.textContent = "Decrypt"; }
});

setMode("CBC");
updateHexHint();
