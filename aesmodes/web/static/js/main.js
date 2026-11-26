/* main.js — AES learning-app navigation and the self-contained Use AES tab.
 * The new tab uses the EXISTING /api/mode endpoint. On GitHub Pages that
 * endpoint runs the project's own Python via Pyodide; no Flask server required.
 * No original navigation tabs or Encryptor links are removed.
 */
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
      el("span", { class: "loop", "data-label": "rounds 1 … Nr−1" }, tag("op-sub", "SubBytes"), tag("op-shift", "ShiftRows"), tag("op-mix", "MixColumns"), tag("op-ark", "AddRoundKey")),
      arrow(),
      el("span", { class: "loop", "data-label": "final round Nr" }, tag("op-sub", "SubBytes"), tag("op-shift", "ShiftRows"), tag("op-ark", "AddRoundKey")),
      arrow(), el("span", { class: "box" }, "ciphertext")
    );
  }

  function installUseAESTab() {
    const nav = $(".nav"), main = $("main");
    if (!nav || !main) return;

    // Add a REAL in-app tab, but preserve every existing navigation link.
    // Also recover gracefully from the earlier mistake where Encryptor was renamed.
    let tab = nav.querySelector('[data-page="simple"]') || nav.querySelector('a[href="#simple"]');
    if (!tab) tab = Array.from(nav.querySelectorAll("a")).find(
      (a) => a.textContent.trim().toLowerCase() === "use aes");
    if (tab) {
      tab.href = "#simple";
      tab.dataset.page = "simple";
      tab.classList.remove("nav-out");
      tab.textContent = "Use AES";
    } else {
      tab = document.createElement("a");
      tab.href = "#simple";
      tab.dataset.page = "simple";
      tab.textContent = "Use AES";
      const encryptor = Array.from(nav.querySelectorAll("a")).find(
        (a) => /encryptor/i.test(a.textContent));
      if (encryptor) nav.insertBefore(tab, encryptor);
      else nav.appendChild(tab);
    }
    // The original Encryptor must remain available as a separate tool.
    if (!Array.from(nav.querySelectorAll("a")).some((a) => /encryptor/i.test(a.textContent))) {
      const original = document.createElement("a");
      original.className = "nav-out";
      original.href = "https://aes-modes-project.github.io/aes-modes-of-operation/encryptor/";
      original.title = "Encrypt your own files and messages";
      original.textContent = "🔒 Encryptor ↗";
      nav.appendChild(original);
    }
    // Replace only an older, potentially broken Use AES section if one exists.
    const oldPage = document.getElementById("page-simple");
    if (oldPage) oldPage.remove();

    const page = document.createElement("section");
    page.id = "page-simple";
    page.className = "page";
    page.innerHTML = `
      <div class="page-head">
        <h1>Use AES</h1>
        <p class="lead">Encrypt or decrypt a message using AES. No lessons, just the tool.</p>
      </div>
      <div class="paper aes-quick-panel">
        <div class="aes-quick-grid">
          <label class="field"><span>Mode</span>
            <select id="quick-mode"><option>ECB</option><option>CBC</option><option>CFB</option><option>OFB</option><option>CTR</option></select>
          </label>
          <div class="field"><span>Action</span>
            <div class="seg big aes-quick-ops" id="quick-action">
              <button type="button" class="on" data-value="encrypt">Encrypt</button>
              <button type="button" data-value="decrypt">Decrypt</button>
            </div>
          </div>
          <label class="field grow aes-quick-key"><span>AES key (32, 48 or 64 hex digits)</span>
            <input id="quick-key" class="mono" spellcheck="false" autocomplete="off" aria-label="AES key in hexadecimal" />
          </label>
        </div>
        <div class="aes-quick-keybuttons">
          <label for="quick-keybits">Key length</label>
          <select id="quick-keybits"><option value="16">AES-128</option><option value="24">AES-192</option><option value="32">AES-256</option></select>
          <button class="btn small" id="quick-generate" type="button">Generate random key</button>
        </div>
        <label class="field aes-quick-counter" id="quick-counter-box" hidden><span>Initial counter (32 hex digits)</span>
          <input id="quick-counter" class="mono" spellcheck="false" value="00000000000000000000000000000001" />
        </label>
        <div class="aes-quick-inputhead">
          <label for="quick-input" id="quick-input-label">Message to encrypt</label>
          <div class="seg" id="quick-format">
            <button type="button" data-format="text" class="on">Text</button>
            <button type="button" data-format="hex">Hex</button>
          </div>
        </div>
        <textarea id="quick-input" class="mono aes-quick-input" placeholder="Type or paste your message here..." spellcheck="false"></textarea>
        <div class="aes-quick-actions">
          <span id="quick-length" class="muted" aria-live="polite">0 bytes (UTF-8)</span>
          <span class="aes-quick-spacer"></span>
          <button type="button" class="btn" id="quick-clear">Clear</button>
          <button type="button" class="btn primary" id="quick-run">Encrypt message</button>
        </div>
        <p class="error" id="quick-error" role="alert" hidden></p>
        <p id="quick-status" class="muted" aria-live="polite"></p>
        <div id="quick-result" hidden class="aes-quick-result">
          <div class="aes-quick-result-head"><h2>Result</h2>
            <span id="quick-result-meta" class="muted"></span>
          </div>
          <label for="quick-output" id="quick-output-label">Ciphertext (hex)</label>
          <textarea id="quick-output" readonly class="mono aes-quick-output"></textarea>
          <div class="aes-quick-actions">
            <button type="button" class="btn" id="quick-copy">Copy result</button>
            <button type="button" class="btn" id="quick-download">Download .txt</button>
            <button type="button" class="btn primary" id="quick-switch">Decrypt this ciphertext →</button>
          </div>
          <div id="quick-decrypted-hex-wrap" hidden><p class="muted">Plaintext (hex)</p>
            <textarea id="quick-decrypted-hex" class="mono aes-quick-output" readonly></textarea>
          </div>
        </div>
      </div>
      <p class="aes-quick-note muted">Class-project settings: fixed zero IV for CBC, CFB and OFB; user-selected CTR counter; zero padding followed by its count. Educational use only, not for storing sensitive data. For large files, use the existing Encryptor.</p>
    `;
    main.appendChild(page);

    const style = document.createElement("style");
    style.id = "use-aes-inline-style";
    style.textContent = `
      .aes-quick-panel { padding: 26px; margin-bottom: 12px; }
      .aes-quick-grid { display:grid; grid-template-columns:minmax(110px,130px) minmax(148px,168px) minmax(240px,1fr); gap:14px; align-items:end; }
      .aes-quick-grid .field, .aes-quick-counter { display:flex; flex-direction:column; gap:7px; min-width:0; }
      .aes-quick-grid input, .aes-quick-grid select, .aes-quick-counter input, .aes-quick-keybuttons select { border:1px solid var(--rule-strong); background:var(--sheet); border-radius:6px; min-height:38px; padding:8px 11px; color:var(--ink); max-width:100%; }
      .aes-quick-keybuttons { display:flex; align-items:center; flex-wrap:wrap; gap:10px; margin-top:12px; margin-bottom:16px; font-size:13px; color:var(--muted); }
      .aes-quick-keybuttons select { min-height:32px; padding:5px 8px; }
      .aes-quick-counter { max-width:400px; margin:12px 0 16px; }
      .aes-quick-inputhead { display:flex; justify-content:space-between; align-items:center; gap:14px; margin:18px 0 8px; }
      .aes-quick-input, .aes-quick-output { display:block; width:100%; box-sizing:border-box; resize:vertical; border:1px solid var(--rule-strong); border-radius:7px; background:white; padding:15px; color:var(--ink); font-size:15px; line-height:1.55; }
      .aes-quick-input { min-height:195px; } .aes-quick-output { min-height:100px; margin-top:10px; }
      .aes-quick-actions { display:flex; align-items:center; gap:9px; flex-wrap:wrap; margin-top:15px; }
      .aes-quick-spacer {flex:1;}
      .aes-quick-result {border-top:1px solid var(--rule); padding-top:20px; margin-top:18px;}
      .aes-quick-result-head {display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:12px;}
      .aes-quick-result-head h2 {margin:0;}
      .aes-quick-note {margin:18px 0 45px;font-size:13px;}
      #quick-status {font-size:13px; margin:6px 0 0;}
      #quick-error {margin:12px 0;}
      #quick-decrypted-hex-wrap {margin-top:16px;}
      @media(max-width:900px){.aes-quick-grid {grid-template-columns:1fr 1fr;}.aes-quick-grid .aes-quick-key{grid-column:1/-1;}}
      @media(max-width:540px){.aes-quick-grid{grid-template-columns:1fr;}.aes-quick-grid .aes-quick-key{grid-column:auto;}.aes-quick-panel{padding:17px;}.aes-quick-input{min-height:160px;}}
    `;
    document.head.appendChild(style);

    let operation = "encrypt", dataFormat = "text", last = null;
    const byId = (id) => document.getElementById(id);
    const modeField = byId("quick-mode"), keyField = byId("quick-key"), inputField = byId("quick-input");
    const counterField = byId("quick-counter");

    function randomKey() {
      const bytes = new Uint8Array(Number(byId("quick-keybits").value));
      window.crypto.getRandomValues(bytes);
      keyField.value = Array.from(bytes, (n) => n.toString(16).padStart(2, "0")).join("");
      invalidate();
    }
    function invalidate() {
      byId("quick-result").hidden = true;
      byId("quick-error").hidden = true;
      byId("quick-status").textContent = "";
    }
    function updateLength() {
      const text = inputField.value;
      if (operation === "decrypt" || dataFormat === "hex") {
        const filtered = text.replace(/\s+/g, "");
        byId("quick-length").textContent = `${Math.floor(filtered.length / 2)} bytes (hex)`;
      } else {
        byId("quick-length").textContent = `${new TextEncoder().encode(text).length} bytes (UTF-8)`;
      }
    }
    function updateMode() {
      byId("quick-counter-box").hidden = modeField.value !== "CTR";
      invalidate();
    }
    function updateOperation(next) {
      operation = next;
      byId("quick-action").querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.value === next));
      byId("quick-input-label").textContent = next === "encrypt" ? "Message to encrypt" : "Ciphertext (hex)";
      byId("quick-run").textContent = next === "encrypt" ? "Encrypt message" : "Decrypt message";
      byId("quick-format").hidden = next === "decrypt";
      inputField.placeholder = next === "encrypt" ? "Type or paste your message here..." : "Paste hexadecimal ciphertext here...";
      invalidate(); updateLength();
    }
    function updateFormat(next) {
      dataFormat = next;
      byId("quick-format").querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.format === next));
      inputField.placeholder = next === "hex" ? "Paste hexadecimal bytes here..." : "Type or paste your message here...";
      invalidate(); updateLength();
    }
    function showError(error) {
      byId("quick-error").textContent = error.message || String(error);
      byId("quick-error").hidden = false;
      byId("quick-status").textContent = "";
    }
    async function run() {
      invalidate();
      const mode = modeField.value;
      const key = keyField.value.trim().replace(/\s/g, "");
      const data = inputField.value;
      if (!/^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})$/.test(key)) {
        showError(new Error("The AES key must contain exactly 32, 48, or 64 hexadecimal digits.")); return;
      }
      const hex = operation === "decrypt" || dataFormat === "hex";
      if (hex && !/^(?:[\da-fA-F]{2}\s*)*$/.test(data.trim())) {
        showError(new Error("Please enter complete hexadecimal bytes (two digits per byte).")); return;
      }
      if (operation === "decrypt" && data.replace(/\s/g, "").length === 0) {
        showError(new Error("Paste ciphertext before decrypting.")); return;
      }
      const size = hex ? data.replace(/\s/g, "").length / 2 : new TextEncoder().encode(data).length;
      // The existing teaching API builds one trace per block; don't freeze a browser with huge files.
      if (size > 32768) {
        showError(new Error("This tab handles messages up to 32 KiB. For larger files, use the Encryptor link in the top navigation.")); return;
      }
      if (mode === "CTR" && !/^[0-9a-fA-F]{32}$/.test(counterField.value.trim())) {
        showError(new Error("The initial CTR counter needs exactly 32 hexadecimal digits.")); return;
      }
      const btn = byId("quick-run");
      btn.disabled = true;
      btn.textContent = "Working…";
      byId("quick-status").textContent = "Processing with the project's AES code…";
      // Give the UI a chance to paint before Pyodide computes.
      await new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 10)));
      try {
        const result = await api("/api/mode", {
          mode, operation, key,
          data, dataFormat: hex ? "hex" : "text",
          counter: mode === "CTR" ? counterField.value.trim() : null
        });
        last = { operation, mode, key, counter: counterField.value, result };
        const plaintext = operation === "decrypt";
        byId("quick-output-label").textContent = plaintext ? (result.outputText === null ? "Plaintext (hex)" : "Plaintext (text)") : "Ciphertext (hex)";
        byId("quick-output").value = plaintext ? (result.outputText ?? result.output) : result.output;
        byId("quick-decrypted-hex-wrap").hidden = !plaintext || result.outputText === null;
        if (plaintext && result.outputText !== null) byId("quick-decrypted-hex").value = result.output;
        byId("quick-result-meta").textContent = `${result.mode} · AES-${result.keyBits} · ${result.output.length / 2} bytes`;
        byId("quick-switch").textContent = plaintext ? "Encrypt it again →" : "Decrypt this ciphertext →";
        byId("quick-result").hidden = false;
        byId("quick-status").textContent = "Completed.";
      } catch (error) {
        showError(error);
      } finally {
        btn.disabled = false;
        btn.textContent = operation === "encrypt" ? "Encrypt message" : "Decrypt message";
      }
    }
    function switchOperation() {
      if (!last) return;
      const r = last.result;
      const old = last.operation;
      if (old === "encrypt") {
        updateOperation("decrypt");
        inputField.value = r.output;
      } else {
        updateOperation("encrypt");
        inputField.value = r.outputText ?? r.output;
        updateFormat(r.outputText === null ? "hex" : "text");
      }
      modeField.value = last.mode;
      keyField.value = last.key;
      counterField.value = last.counter;
      updateMode(); updateLength();
      run();
    }
    byId("quick-action").addEventListener("click", (event) => {
      const b = event.target.closest("button[data-value]");
      if (b) updateOperation(b.dataset.value);
    });
    byId("quick-format").addEventListener("click", (event) => {
      const b = event.target.closest("button[data-format]");
      if (b) updateFormat(b.dataset.format);
    });
    modeField.addEventListener("change", updateMode);
    byId("quick-generate").addEventListener("click", randomKey);
    byId("quick-keybits").addEventListener("change", randomKey);
    byId("quick-run").addEventListener("click", run);
    byId("quick-clear").addEventListener("click", () => { inputField.value = ""; invalidate(); updateLength(); inputField.focus(); });
    inputField.addEventListener("input", () => { invalidate(); updateLength(); });
    keyField.addEventListener("input", invalidate);
    counterField.addEventListener("input", invalidate);
    byId("quick-switch").addEventListener("click", switchOperation);
    byId("quick-copy").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(byId("quick-output").value); byId("quick-status").textContent = "Copied."; }
      catch (e) { byId("quick-output").select(); byId("quick-status").textContent = "Select and copy the result."; }
    });
    byId("quick-download").addEventListener("click", () => {
      const content = byId("quick-output").value;
      const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
      const link = document.createElement("a");
      link.href = url; link.download = operation === "decrypt" ? "aes-plaintext.txt" : "aes-ciphertext-hex.txt";
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    randomKey(); updateMode(); updateLength();
    App.pages.simple = { init() {}, run() {} };
  }

  function show() {
    const page = (location.hash || "#home").slice(1);
    const known = ["home", "aes", "keys", "modes", "lab", "simple"];
    const p = known.includes(page) ? page : "home";
    $$(".page").forEach((s) => s.classList.toggle("active", s.id === `page-${p}`));
    $$(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === p));
    syncKeyInputs();
    if (!started[p] && App.pages[p] && App.pages[p].run) { started[p] = true; App.pages[p].run(); }
    window.scrollTo({ top: 0 });
  }

  document.addEventListener("DOMContentLoaded", () => {
    installUseAESTab();
    Object.values(App.pages).forEach((pg) => pg.init && pg.init());
    homeDiagram();
    window.addEventListener("hashchange", show);
    show();
    api("/api/version").then((v) => {
      $("#version").textContent = `· aesmodes v${v.version} · ` +
        (App.backend === "browser" ? "running in your browser (Pyodide)" : "running on the local Python server");
    }).catch(() => {});
  });
})();
