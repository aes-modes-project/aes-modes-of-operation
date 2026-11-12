/* lab.js - page 4: experiments that show what the modes mean in practice. */
"use strict";

App.pages.lab = (() => {
  const MODES = ["ECB", "CBC", "CFB", "OFB", "CTR"];
  const SIZE = 128;
  let source = null;          // Uint8Array of SIZE*SIZE gray pixels

  function init() {
    $("#img-run").addEventListener("click", runImages);
    $("#img-file").addEventListener("change", loadFile);
    let t;
    const onFlip = () => {
      $("#flip-byte-val").textContent = $("#flip-byte").value;
      $("#flip-bit-val").textContent = $("#flip-bit").value;
      clearTimeout(t); t = setTimeout(runFlip, 120);
    };
    ["#flip-byte", "#flip-bit"].forEach((s) => $(s).addEventListener("input", onFlip));
    $("#flip-msg").addEventListener("change", runFlip);
    $("#iv-run").addEventListener("click", runIV);
    buildCompare();
  }

  function run() {
    source = source || drawDefaultImage();
    showImages({});
    runFlip(); runIV();
  }

  /* ---------------------------------------------------------------- 4.1 picture */
  function drawDefaultImage() {
    const c = el("canvas", { width: SIZE, height: SIZE }), g = c.getContext("2d");
    g.fillStyle = "#e6e6e6"; g.fillRect(0, 0, SIZE, SIZE);
    g.fillStyle = "#3c3c3c"; g.beginPath(); g.arc(64, 70, 46, 0, Math.PI * 2); g.fill();
    g.fillStyle = "#9a9a9a"; g.fillRect(34, 14, 60, 30);                  // padlock shackle
    g.fillStyle = "#e6e6e6"; g.fillRect(48, 24, 32, 24);
    g.fillStyle = "#ffffff"; g.font = "bold 34px Georgia, serif"; g.textAlign = "center"; g.fillText("AES", 64, 84);
    g.fillStyle = "#000000"; for (let y = 116; y < 128; y += 6) g.fillRect(0, y, 128, 3);
    return toGray(g.getImageData(0, 0, SIZE, SIZE), false);
  }

  /* gray levels; photos are reduced to 4 levels so they have large flat areas */
  function toGray(img, posterize) {
    const out = new Uint8Array(SIZE * SIZE);
    for (let i = 0; i < out.length; i++) {
      let v = Math.round(0.299 * img.data[4 * i] + 0.587 * img.data[4 * i + 1] + 0.114 * img.data[4 * i + 2]);
      if (posterize) v = Math.min(255, Math.round(v / 85) * 85);
      out[i] = v;
    }
    return out;
  }

  function loadFile(e) {
    const f = e.target.files[0];
    if (!f) return;
    const img = new Image();
    img.onload = () => {
      const c = el("canvas", { width: SIZE, height: SIZE }), g = c.getContext("2d");
      const s = Math.min(img.width, img.height);
      g.drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, SIZE, SIZE);
      source = toGray(g.getImageData(0, 0, SIZE, SIZE), true);
      showImages({});
      runImages();
    };
    img.src = URL.createObjectURL(f);
  }

  function grayCanvas(bytes) {
    const c = el("canvas", { width: SIZE, height: SIZE }), g = c.getContext("2d");
    const img = g.createImageData(SIZE, SIZE);
    for (let i = 0; i < SIZE * SIZE; i++) {
      const v = bytes ? bytes[i] : 200;
      img.data.set([v, v, v, 255], 4 * i);
    }
    g.putImageData(img, 0, 0);
    return c;
  }

  const CAPTIONS = {
    ECB: "outline still visible", CBC: "noise", CFB: "noise", OFB: "noise", CTR: "noise",
  };
  function showImages(enc) {
    const grid = $("#img-grid");
    grid.innerHTML = "";
    grid.append(el("div", { class: "img-card" }, grayCanvas(source), el("p", {}, "original"), el("small", {}, `${SIZE}×${SIZE} pixels = ${SIZE * SIZE / 16} blocks`)));
    MODES.forEach((m) => grid.append(el("div", { class: "img-card" }, grayCanvas(enc[m]),
      el("p", { html: `<span class="mode-chip m-${m}">${m}</span>` }), el("small", {}, enc[m] ? CAPTIONS[m] : "not encrypted yet"))));
  }

  const b64 = (u8) => { let s = ""; u8.forEach((b) => (s += String.fromCharCode(b))); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function runImages() {
    const status = $("#img-status");
    const enc = {};
    try {
      for (const m of MODES) {
        status.innerHTML = `<span class="spinner"></span> encrypting with ${m}… (${SIZE * SIZE / 16} AES blocks in Python)`;
        const r = await api("/api/image", { mode: m, key: App.state.key, counter: "1", pixels: b64(source) });
        enc[m] = unb64(r.pixels);
        showImages(enc);
      }
      status.textContent = "Done. Each 16-pixel run of one gray level is one AES block.";
    } catch (err) { status.textContent = err.message; }
  }

  /* ---------------------------------------------------------------- 4.2 bit flip */
  async function runFlip() {
    let r;
    try {
      r = await api("/api/bitflip", { key: App.state.key, message: $("#flip-msg").value, messageFormat: "text",
        counter: "1", byte: +$("#flip-byte").value, bit: +$("#flip-bit").value });
    } catch (err) { $("#flip-table").textContent = err.message; return; }
    const slider = $("#flip-byte");
    slider.max = r.ciphertextLength - 1;
    if (+slider.value > slider.max) slider.value = slider.max;
    const n = r.modes[0].blocks.length;
    const grid = el("div", { class: "flip-grid", style: { gridTemplateColumns: `60px repeat(${n}, minmax(34px, 1fr))` } });
    grid.append(el("div", {}));
    for (let b = 0; b < n; b++) grid.append(el("div", { class: "fhead" }, b === r.block ? `▼ ${b + 1}` : `${b + 1}`));
    r.modes.forEach((m) => {
      grid.append(el("div", { class: "mname" }, el("span", { class: `mode-chip m-${m.mode}` }, m.mode)));
      m.blocks.forEach((b, k) => grid.append(el("div", {
        class: `fc ${b.bits === 0 ? "e0" : b.bits <= 8 ? "e1" : "e2"}${k === r.block ? " hit" : ""}`,
        title: `block ${k + 1}: ${b.bits} bits wrong\noriginal ${b.original}\ndamaged  ${b.damaged}`,
      }, b.bits === 0 ? "·" : b.bits)));
    });
    $("#flip-table").innerHTML = "";
    $("#flip-table").append(
      el("p", { class: "muted", html: `Flipping bit ${r.bit} of byte ${r.byte}, which is in ciphertext block <b>${r.block + 1}</b> (marked ▼). Hover a cell to see the original and damaged block.` }),
      grid);
  }

  /* ---------------------------------------------------------------- 4.3 zero IV */
  async function runIV() {
    const a = $("#iv-a").value, b = $("#iv-b").value;
    const out = $("#iv-table");
    out.innerHTML = '<span class="spinner"></span>';
    try {
      const rows = [];
      for (const m of MODES) {
        const ra = await api("/api/mode", { mode: m, operation: "encrypt", key: App.state.key, data: a, dataFormat: "text", counter: "1" });
        const rb = await api("/api/mode", { mode: m, operation: "encrypt", key: App.state.key, data: b, dataFormat: "text", counter: "1" });
        rows.push([m, ra.output.match(/.{32}/g), rb.output.match(/.{32}/g)]);
      }
      const t = el("table", { class: "booktabs" },
        el("thead", {}, el("tr", {}, el("th", {}, "mode"), el("th", {}, "ciphertext of A (blocks)"), el("th", {}, "ciphertext of B (blocks)"), el("th", { class: "c" }, "equal blocks"))),
        el("tbody", {}, rows.map(([m, A, B]) => {
          const same = A.map((x, i) => x === B[i]);
          const chips = (L) => el("div", { class: "iv-blocks" }, L.map((x, i) => el("span", { class: "ivb" + (same[i] ? " same" : ""), title: x }, x.slice(0, 6) + "…")));
          return el("tr", {}, el("td", {}, el("span", { class: `mode-chip m-${m}` }, m)), el("td", {}, chips(A)), el("td", {}, chips(B)),
            el("td", { class: "c" }, `${same.filter(Boolean).length} of ${A.length}`));
        })));
      out.innerHTML = "";
      out.append(el("p", { class: "caption", html: "<b>Table 2.</b> Red blocks are identical in both ciphertexts." }), t,
        el("p", { class: "why", html: "Because the IV (and the CTR counter) is the same for both messages, every mode reveals that the two messages <b>start the same way</b>. In ECB, the identical blocks after the difference also show up. In OFB and CTR, the same keystream is reused, so C<sub>A</sub> ⊕ C<sub>B</sub> = P<sub>A</sub> ⊕ P<sub>B</sub>. That's why real systems use a fresh random IV or nonce for every message." }));
    } catch (err) { out.textContent = err.message; }
  }

  /* ---------------------------------------------------------------- 4.4 comparison */
  function buildCompare() {
    const yes = "✓", no = "✗";
    const rows = [
      ["encryption", ["C_i = E_K(P_i)", "C_i = E_K(P_i \\oplus C_{i-1})", "C_i = P_i \\oplus E_K(C_{i-1})", "C_i = P_i \\oplus O_i", "C_i = P_i \\oplus E_K(T_i)"], true],
      ["IV / counter", ["none", "IV = 0", "IV = 0", "IV = 0", "user's T₁"]],
      ["needs AES decryption", [yes, yes, no, no, no]],
      ["parallel encryption", [yes, no, no, no, yes]],
      ["parallel decryption", [yes, yes, yes, no, yes]],
      ["hides repeated blocks", [no, yes, yes, yes, yes]],
      ["1 flipped ciphertext bit", ["1 block garbled", "1 block + 1 bit", "1 bit + 1 block", "1 bit", "1 bit"]],
      ["used today", ["single blocks only", "legacy TLS, files", "stream links", "noisy channels", "AES-GCM, TLS 1.3"]],
    ];
    const t = el("table", { class: "booktabs" },
      el("thead", {}, el("tr", {}, el("th", {}, ""), MODES.map((m) => el("th", { class: "c" }, el("span", { class: `mode-chip m-${m}` }, m))))),
      el("tbody", {}, rows.map(([k, vals, isTex]) => el("tr", {}, el("td", { class: "muted" }, k),
        vals.map((v) => el("td", { class: "c" }, isTex ? tex(v) : v))))));
    $("#cmp-table").append(el("p", { class: "caption", html: "<b>Table 3.</b> Properties of the five modes (every row is checked by a test in <code>tests/test_modes.py</code>)." }), t);
  }

  return { init, run };
})();
