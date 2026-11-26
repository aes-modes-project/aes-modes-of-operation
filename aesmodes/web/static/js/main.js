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
    // Make the practical tool the first, visually highlighted navigation option.
    const overviewLink = nav.querySelector('[data-page="home"]');
    if (overviewLink) nav.insertBefore(tab, overviewLink);
    tab.classList.add("aes-quick-link");
    tab.setAttribute("aria-label", "Use AES: encrypt or decrypt a message");

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
          <button class="btn small" id="quick-copy-key" type="button">Copy key</button>
          <span class="aes-key-reminder">Keep the same key to decrypt later.</span>
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
        <p class="aes-format-hint muted" id="quick-format-hint">Use <b>Text</b> for normal messages. <b>Hex</b> accepts only numbers 0–9 and letters A–F.</p>
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
       <details class="aes-guide"><summary>How do I encrypt and decrypt a message?</summary>
         <ol><li>Choose a mode and <b>Text</b>, then write your message.</li>
         <li>Click <b>Encrypt message</b>. Copy the resulting hexadecimal ciphertext if you want to share or save it.</li>
         <li>Use <b>Decrypt this ciphertext →</b> to recover your message automatically. If decrypting later, use the exact same AES key, mode, and counter (for CTR).</li></ol>
       </details>
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
       .aes-format-hint { margin:7px 0 0;font-size:13.5px;line-height:1.45; }
       .aes-key-reminder {font-size:13px;color:var(--muted);}
       .aes-guide {background:var(--sheet);border:1px solid var(--rule);border-radius:10px;padding:13px 18px;margin:18px 0 0;}
       .aes-guide summary {cursor:pointer;font-size:15px;font-weight:bold;}
       .aes-guide ol {font-size:14px;line-height:1.8;margin-bottom:0;}
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
      invalidate(); updateLength(); updateHint();
    }
    function updateHint() {
      byId("quick-format-hint").innerHTML = operation === "decrypt"
        ? "Paste <b>hexadecimal ciphertext</b> and use the <b>same AES key and mode</b> you used to encrypt (and the same counter for CTR)."
        : dataFormat === "text"
          ? "<b>Text</b> is for normal messages, including spaces and emojis. Choose <b>Hex</b> only for hexadecimal bytes."
          : "<b>Hex</b> only accepts the digits 0–9 and letters A–F, in pairs. For normal words, click <b>Text</b>.";
    }
    function updateFormat(next) {
      dataFormat = next;
      byId("quick-format").querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.format === next));
      inputField.placeholder = next === "hex" ? "Paste hexadecimal bytes here..." : "Type or paste your message here...";
      invalidate(); updateLength(); updateHint();
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
    byId("quick-copy-key").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(keyField.value);
        byId("quick-status").textContent = "Key copied. Keep it for decryption; a new random key will be generated when this page reloads.";
      } catch (e) {
        keyField.focus(); keyField.select();
        byId("quick-status").textContent = "Key selected — press Command+C (Mac) or Ctrl+C to copy.";
      }
    });
    byId("quick-keybits").addEventListener("change", randomKey);
    byId("quick-run").addEventListener("click", run);
    byId("quick-clear").addEventListener("click", () => { inputField.value = ""; invalidate(); updateLength(); inputField.focus(); });
    inputField.addEventListener("input", () => { invalidate(); updateLength(); });
    keyField.addEventListener("input", () => {
      invalidate();
      const digits = keyField.value.replace(/\s/g, "").length;
      if ([32,48,64].includes(digits)) byId("quick-keybits").value = String(digits / 2);
    });
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
    randomKey(); updateMode(); updateLength(); updateHint();
    App.pages.simple = { init() {}, run() {} };
  }


  const learningJourney = [
    { id: "home", label: "Overview" },
    { id: "aes", label: "Learn AES" },
    { id: "keys", label: "Key expansion" },
    { id: "modes", label: "Modes of operation" },
    { id: "lab", label: "Experiments" },
    { id: "simple", label: "Use AES" },
  ];

  function improveNavigation() {
    const main = $("main"), nav = $(".nav");
    if (!main || !nav) return;

    // Rename the lesson everywhere it appears in the educational interface.
    const learnLink = nav.querySelector('[data-page="aes"]');
    if (learnLink) learnLink.innerHTML = '<span class="num">1</span>Learn AES';
    const learnCard = $('#page-home .cards4 a[href="#aes"] h3');
    if (learnCard) learnCard.textContent = "Learn AES";
    const learnHeading = $('#page-aes .page-head h1');
    if (learnHeading) {
      const titleText = Array.from(learnHeading.childNodes).find(n => n.nodeType === Node.TEXT_NODE);
      if (titleText) titleText.textContent = "Learn AES, step by step";
    }

    // The overview makes it obvious how to begin: use AES immediately or learn it.
    const hero = $('#page-home .hero');
    if (hero && !$('#aes-get-started')) {
      const choices = document.createElement("div");
      choices.className = "aes-choices";
      choices.id = "aes-get-started";
      choices.innerHTML = `
        <div class="aes-choices-copy">
          <span class="aes-eyebrow">NEW HERE? CHOOSE YOUR PATH</span>
          <strong>What would you like to do?</strong>
          <span>Encrypt a message right away, or explore how AES works with interactive lessons.</span>
        </div>
        <div class="aes-choices-actions">
          <a class="aes-choice-primary" href="#simple">Use AES <span aria-hidden="true">→</span></a>
          <a class="aes-choice-secondary" href="#aes">Learn AES <span aria-hidden="true">→</span></a>
        </div>`;
      hero.insertAdjacentElement("afterend", choices);
    }

    // Keep a single, clear previous/next navigation bar at the bottom of
    // each page, after the content. No duplicate arrows above the lessons.
    learningJourney.forEach((step, i) => {
      const section = document.getElementById(`page-${step.id}`);
      if (!section) return;
      const previous = learningJourney[i - 1];
      const next = learningJourney[i + 1];
      const pager = document.createElement("nav");
      pager.className = "aes-page-pager";
      pager.setAttribute("aria-label", "Continue through the AES lessons");
      pager.innerHTML = `
        <div class="aes-page-pager-prev">${previous
          ? `<a href="#${previous.id}" aria-label="Previous: ${previous.label}">← <span><small>Previous</small>${previous.label}</span></a>`
          : '<span class="aes-endpoint">Beginning of the guide</span>'}</div>
        <span class="aes-page-progress">${step.id === "simple" ? "Try AES" : `${i + 1} / 5`}</span>
        <div class="aes-page-pager-next">${next
          ? `<a href="#${next.id}" aria-label="Next: ${next.label}"><span><small>Next</small>${next.label}</span> →</a>`
          : '<a href="#home" aria-label="Return to overview"><span><small>Finished!</small>Back to overview</span> ↻</a>'}</div>`;
      section.appendChild(pager);
    });

    const style = document.createElement("style");
    style.id = "aes-navigation-ux-style";
    style.textContent = `
      /* Distinct teal primary action against the existing cream-and-ink UI. */
      .nav {align-items:center;}
      .nav a {white-space:nowrap;}
      .nav a.aes-quick-link {background:#e3f3ed;color:#105747;border:1px solid #a5cfc0;
        font-weight:700;padding:8px 13px;transition:background .15s,box-shadow .15s;}
      .nav a.aes-quick-link:hover {background:#cfebdf;box-shadow:0 2px 8px rgba(16,87,71,.12);}
      .nav a.aes-quick-link.active {background:#115d4d;border-color:#115d4d;color:white;}
      .nav a:focus-visible, .aes-page-pager a:focus-visible,
      .aes-choices a:focus-visible {outline:3px solid #2c7a68;outline-offset:3px;}
      .aes-choices {display:flex;align-items:center;justify-content:space-between;gap:22px;
        background:#edf5f1;border:1px solid #c3dfd3;border-radius:12px;padding:20px 24px;margin:2px 0 24px;}
      .aes-choices-copy {display:flex;flex-direction:column;gap:5px;}
      .aes-choices-copy strong {font-size:21px;color:#154f43;}
      .aes-choices-copy>span:last-child {font-size:14.5px;color:#475b54;line-height:1.5;}
      .aes-eyebrow {font-family:var(--mono);font-size:11px;letter-spacing:.7px;color:#2e7865;}
      .aes-choices-actions {display:flex;gap:10px;flex-wrap:wrap;flex-shrink:0;}
      .aes-choices-actions a {display:inline-flex;align-items:center;gap:9px;text-decoration:none;
        padding:10px 15px;border-radius:7px;font-weight:700;font-size:15px;white-space:nowrap;}
      .aes-choice-primary {background:#115d4d;color:#fff;}
      .aes-choice-primary:hover {background:#0c483b;color:#fff;}
      .aes-choice-secondary {background:#fff;color:#155c4d;border:1px solid #8ebdab;}
      .aes-choice-secondary:hover {background:#f5faf7;}
      .aes-page-pager {display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:center;
        border-top:1px solid var(--rule);margin-top:35px;padding:20px 0 2px;}
      .aes-page-pager a {display:inline-flex;align-items:center;gap:12px;padding:11px 14px;
        border:1px solid var(--rule);border-radius:8px;color:var(--ink);text-decoration:none;
        background:var(--sheet);font-size:22px;max-width:100%;}
      .aes-page-pager a:hover {border-color:#115d4d;color:#115d4d;background:#edf5f1;}
      .aes-page-pager a span {display:flex;flex-direction:column;gap:2px;font-size:15px;font-weight:600;}
      .aes-page-pager a small {font-size:12px;font-weight:400;color:var(--muted);}
      .aes-page-pager-next {text-align:right;}
      .aes-page-pager-next a {margin-left:auto;}
      .aes-page-progress,.aes-endpoint {font-family:var(--mono);font-size:12px;color:var(--muted);}
      @media(max-width:1120px){.aes-choices{align-items:flex-start;flex-direction:column;}}
      @media(max-width:750px){
        .topbar {gap:10px;}
        .topbar .nav {display:flex;flex-wrap:nowrap;width:100%;max-width:100%;overflow-x:auto;
          overscroll-behavior-inline:contain;padding:3px 0 9px;margin:0;scrollbar-width:thin;}
        .nav a {flex:0 0 auto;}
        .aes-choices {padding:16px;}
        .aes-choices-actions{width:100%;}
        .aes-choices-actions a {justify-content:center;flex:1 1 125px;}
        .aes-page-pager {grid-template-columns:1fr 1fr;gap:10px;}
        .aes-page-progress {display:none;}
        .aes-page-pager a {padding:10px;font-size:17px;}
        .aes-page-pager a span{font-size:13px;}
      }
    `;
    document.head.appendChild(style);
  }

  function updateJourney(page) {
    const step = learningJourney.find((item) => item.id === page);
    if (step) document.title = `${step.label} · AES step by step`;
  }

  function show() {
    const page = (location.hash || "#home").slice(1);
    const known = ["home", "aes", "keys", "modes", "lab", "simple"];
    const p = known.includes(page) ? page : "home";
    $$(".page").forEach((s) => s.classList.toggle("active", s.id === `page-${p}`));
    $$(".nav a").forEach((a) => {
      const active = a.dataset.page === p;
      a.classList.toggle("active", active);
      if (active) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    updateJourney(p);
    syncKeyInputs();
    if (!started[p] && App.pages[p] && App.pages[p].run) { started[p] = true; App.pages[p].run(); }
    window.scrollTo({ top: 0 });
  }

  document.addEventListener("DOMContentLoaded", () => {
    installUseAESTab();
    improveNavigation();
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
