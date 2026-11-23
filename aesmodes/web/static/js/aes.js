/* aes.js - page 1: step through the encryption of one AES block. */
"use strict";

App.pages.aes = (() => {
  let data = null;      // response of /api/aes
  let cur = 0;          // current step index
  let sel = [0, 0];     // selected cell (row, col) for SubBytes / AddRoundKey / MixColumns
  let timer = null;
  let sbox = null;
  let fmt;

  const ABBR = { Input: "In", AddRoundKey: "⊕K", SubBytes: "SB", ShiftRows: "SR", MixColumns: "MC" };
  const OPCLASS = { Input: "op-input", AddRoundKey: "op-ark", SubBytes: "op-sub", ShiftRows: "op-shift", MixColumns: "op-mix" };

  /* ---------------------------------------------------------------- setup */
  function init() {
    bindKeyInput($("#aes-key"), () => run());
    $("#aes-block").value = "3243f6a8885a308d313198a2e0370734";
    fmt = segmented("aes-fmt");
    $("#aes-run").addEventListener("click", run);
    // FIPS-197 worked examples: Appendix B for AES-128, Appendix C.2 / C.3 for AES-192 / AES-256
    const EXAMPLES = {
      128: ["2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734"],
      192: ["000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff"],
      256: ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff"],
    };
    $("#aes-example").addEventListener("click", () => {
      const [k, p] = EXAMPLES[keyBits($("#aes-key").value) || 128];
      App.setKey(k); syncKeyInputs();
      $("#aes-block").value = p; fmt.set("hex"); run();
    });
    [$("#aes-key"), $("#aes-block")].forEach((i) => i.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); }));
    $("#aes-first").addEventListener("click", () => go(0));
    $("#aes-prev").addEventListener("click", () => go(cur - 1));
    $("#aes-next").addEventListener("click", () => go(cur + 1));
    $("#aes-last").addEventListener("click", () => go(data.steps.length - 1));
    $("#aes-play").addEventListener("click", togglePlay);
    $("#aes-slider").addEventListener("input", (e) => go(+e.target.value));
    document.addEventListener("keydown", (e) => {
      if (location.hash !== "#aes" || !data || e.target.tagName === "INPUT") return;
      if (e.key === "ArrowRight") { go(cur + 1); e.preventDefault(); }
      if (e.key === "ArrowLeft") { go(cur - 1); e.preventDefault(); }
      if (e.key === " ") { togglePlay(); e.preventDefault(); }
    });
    api("/api/sbox").then((d) => { sbox = d.sbox; });
  }

  async function run() {
    stop();
    App.setKey($("#aes-key").value); syncKeyInputs();
    showError("aes-error", null);
    try {
      data = await api("/api/aes", { key: App.state.key, block: $("#aes-block").value, blockFormat: fmt.get() });
    } catch (err) { showError("aes-error", err); return; }
    const note = $("#aes-note");
    note.hidden = !data.note; note.textContent = data.note || "";
    $("#aes-slider").max = data.steps.length - 1;
    $("#aes-nsteps").textContent = data.steps.length;
    $("#aes-ct").textContent = groupHex(data.ciphertext);
    buildTimeline();
    buildJourney();
    go(0);
  }

  /* called from the Modes page: "open this block in the AES visualizer" */
  function load(keyHex, blockHex) {
    App.setKey(keyHex); syncKeyInputs();
    $("#aes-block").value = blockHex; fmt.set("hex");
    location.hash = "#aes";
    run();
  }

  /* ---------------------------------------------------------------- navigation */
  function go(i) {
    if (!data) return;
    cur = Math.max(0, Math.min(data.steps.length - 1, i));
    $("#aes-slider").value = cur;
    $("#aes-count").textContent = `step ${cur + 1} of ${data.steps.length}`;
    $$(".tl-op").forEach((b) => {
      const k = +b.dataset.i;
      b.classList.toggle("cur", k === cur);
      b.classList.toggle("done", k < cur);
    });
    $$(".tl-round").forEach((r) => r.classList.toggle("cur", +r.dataset.round === data.steps[cur].round));
    $$(".journey .j").forEach((j) => j.classList.toggle("cur", +j.dataset.i === cur));
    renderStage();
    if (cur === data.steps.length - 1) stop();
  }
  function togglePlay() { timer ? stop() : play(); }
  function play() {
    if (!data) return;
    if (cur === data.steps.length - 1) go(0);
    $("#aes-play").textContent = "❚❚";
    timer = setInterval(() => go(cur + 1), 2200);
  }
  function stop() { clearInterval(timer); timer = null; $("#aes-play").textContent = "▶"; }

  function buildTimeline() {
    const tl = $("#aes-timeline");
    tl.innerHTML = "";
    const rounds = {};
    data.steps.forEach((s, i) => { (rounds[s.round] = rounds[s.round] || []).push([s, i]); });
    Object.entries(rounds).forEach(([r, steps]) => {
      const ops = el("div", { class: "tl-ops" },
        steps.map(([s, i]) => {
          const b = el("button", { class: `tl-op ${s.op}`, title: `${r === "0" ? "Start" : "Round " + r}: ${s.op}` }, ABBR[s.op]);
          b.dataset.i = i;
          b.addEventListener("click", () => { stop(); go(i); });
          return b;
        }));
      const label = r === "0" ? "start" : `round ${r}`;
      const g = el("div", { class: "tl-round" + (steps.length < 4 ? " r2" : "") }, el("span", { class: "rlabel" }, label), ops);
      g.style.flexGrow = steps.length;
      g.dataset.round = r;
      tl.append(g);
    });
  }

  function buildJourney() {
    const j = $("#aes-journey");
    j.innerHTML = "";
    const add = (m, label, i) => {
      const box = el("div", { class: "j", title: label }, matrix(m, { size: "tiny" }), el("span", {}, label));
      box.dataset.i = i;
      box.addEventListener("click", () => { stop(); go(i); });
      j.append(box);
    };
    add(data.steps[0].after, "plaintext", 0);
    data.steps.forEach((s, i) => {
      if (s.op === "AddRoundKey") add(s.after, s.round === 0 ? "after K₀" : `round ${s.round}`, i);
    });
  }

  /* ---------------------------------------------------------------- stage */
  function renderStage() {
    const s = data.steps[cur];
    const stage = $("#aes-stage");
    stage.innerHTML = "";
    const roundName = s.round === 0 ? "Initial step" : s.round === data.rounds ? `Round ${s.round} (final round)` : `Round ${s.round}`;
    stage.append(el("div", { class: "stage-head" },
      el("h2", {}, roundName), el("span", { class: `op-tag ${OPCLASS[s.op]}`, style: { fontSize: "16px" } }, s.op),
      el("span", { class: "size-badge", title: `${data.keyBits}-bit key: ${data.rounds} rounds` }, `AES-${data.keyBits}`),
      el("span", { class: "muted", style: { marginLeft: "auto", fontSize: "14px" } }, describeRound(s))));
    const visual = el("div", { class: "visual" });
    const text = el("div", { class: "explain" });
    stage.append(el("div", { class: "stage-grid" }, visual, text));
    ({ Input: stInput, AddRoundKey: stARK, SubBytes: stSub, ShiftRows: stShift, MixColumns: stMix })[s.op](s, visual, text);
  }

  function describeRound(s) {
    if (s.round === 0) return `AddRoundKey with round key K₀, before round 1 of ${data.rounds}`;
    if (s.round === data.rounds) return "SubBytes → ShiftRows → AddRoundKey (no MixColumns)";
    return "SubBytes → ShiftRows → MixColumns → AddRoundKey";
  }

  const P = (html) => el("p", { html });
  const formula = (src) => el("div", { class: "formula" }, tex(src, true));
  const why = (html) => el("p", { class: "why", html });

  /* Input -------------------------------------------------------------------------------- */
  function stInput(s, visual, text) {
    const bytes = hexBytes(data.plaintext);
    const strip = el("div", { style: { display: "grid", gridTemplateColumns: "repeat(16, 1fr)", gap: "3px", margin: "8px 0 4px" } });
    const mat = matrix(s.after, { label: "state", onHover: (r, c) => hi(r + 4 * c) });
    bytes.forEach((b, i) => {
      const col = byteColor(b);
      const cell = el("div", { class: "cell", style: { background: col.bg, color: col.fg, height: "40px", flexDirection: "column", fontSize: "13px" } },
        b, el("small", { style: { fontSize: "9.5px", fontFamily: "var(--serif)", opacity: ".8" } }, `b${i}`));
      cell.addEventListener("mouseenter", () => hi(i));
      strip.append(cell);
    });
    function hi(i) {
      $$(".cell", strip).forEach((c, k) => c.classList.toggle("sel", k === i));
      $$(".matrix .cell", mat).forEach((c) => c.classList.toggle("sel", +c.dataset.r + 4 * +c.dataset.c === i));
    }
    visual.append(el("p", { class: "muted", style: { margin: "6px 0 0" } }, "The 16 plaintext bytes (hover one):"), strip,
      el("div", { class: "mat-row" }, mat));
    hi(0);
    text.append(
      P("AES never works on the bytes as a flat list. It arranges them in a 4 × 4 grid called the <b>state</b>, filled <b>column by column</b>: bytes 0–3 form the first column, bytes 4–7 the second, and so on."),
      formula("s_{r,c} = \\text{in}[\\,r + 4c\\,], \\qquad 0 \\le r, c \\le 3"),
      P(`Every operation that follows changes this grid. With a ${data.keyBits}-bit key, AES runs <b>${data.rounds} rounds</b> (10, 12 or 14 for 128-, 192- or 256-bit keys). The block itself is always 16 bytes. At the end, the state is read out column by column again to give the ciphertext.`),
      why("Why a grid? Two of the operations work on <i>rows</i> (ShiftRows) and on <i>columns</i> (MixColumns). Alternating between the two directions is what spreads every byte across the whole block."));
  }

  /* AddRoundKey ---------------------------------------------------------------------------- */
  function stARK(s, visual, text) {
    const [r, c] = sel;
    const pick = (rr, cc) => { sel = [rr, cc]; renderStage(); };
    const k = s.roundKey;
    visual.append(el("div", { class: "mat-row" },
      matrix(s.before, { label: "state", sel, onClick: pick, size: "mid" }),
      el("span", { class: "op-symbol" }, "⊕"),
      matrix(k, { label: `round key <i>K</i><sub>${s.round}</sub>`, sel, onClick: pick, size: "mid" }),
      el("span", { class: "op-symbol" }, "="),
      matrix(s.after, { label: "new state", sel, onClick: pick, size: "mid" })));
    const a = s.before[r][c], b = k[r][c], o = s.after[r][c];
    const bitsRow = (lab, v) => el("tr", {}, el("td", { class: "lab" }, lab), el("td", { class: "bits" }, toBin(v)), el("td", { class: "bits" }, v));
    visual.append(el("div", { class: "detail-box" },
      P(`Byte at row ${r}, column ${c} (click any cell), bit by bit:`),
      el("table", { class: "bits-table" }, bitsRow("state", a), bitsRow("⊕ key", b), bitsRow("= result", o))));
    text.append(
      P(s.round === 0
        ? `Before the first round, the state is combined with <b>round key 0</b>, which is ${data.keyBits === 128 ? "simply the original key" : `the first 16 bytes of the ${data.keyBits / 8}-byte key (the rest of the key is used in round key 1${data.keyBits === 256 ? "" : " and the key schedule"})`}. Without this step, an attacker could undo the first round, since SubBytes and ShiftRows use no key.`
        : `The state is combined with <b>round key ${s.round}</b>, produced by the <a href="#keys">key expansion</a>. This is the only step that uses the key.`),
      formula("s'_{r,c} = s_{r,c} \\oplus k_{r,c}"),
      P("⊕ is XOR: each bit of the result is 1 when exactly one of the two input bits is 1. XOR is its own inverse, so decryption undoes this step by XORing the same key again."),
      why("Why XOR? It is fast, and it is perfectly balanced: if the key bit is unknown, each output bit is equally likely to be 0 or 1."));
  }

  /* SubBytes ------------------------------------------------------------------------------- */
  function stSub(s, visual, text) {
    const [r, c] = sel;
    const pick = (rr, cc) => { sel = [rr, cc]; renderStage(); };
    visual.append(el("div", { class: "mat-row" },
      matrix(s.before, { label: "state", sel, onClick: pick }),
      opArrow("S-box"),
      matrix(s.after, { label: "after SubBytes", sel, onClick: pick })));
    const v = s.before[r][c];
    const hiNib = parseInt(v[0], 16), loNib = parseInt(v[1], 16);
    const grid = el("div", { class: "sbox" }, el("div", {}));
    for (let x = 0; x < 16; x++) grid.append(el("div", { class: "hd" + (x === loNib ? " colhl2" : "") }, x.toString(16)));
    for (let y = 0; y < 16; y++) {
      grid.append(el("div", { class: "hd" + (y === hiNib ? " rowhl" : "") }, y.toString(16)));
      for (let x = 0; x < 16; x++) {
        const val = sbox ? sbox[y * 16 + x] : "··";
        let cls = "";
        if (y === hiNib && x === loNib) cls = "hit"; else if (y === hiNib) cls = "rowhl"; else if (x === loNib) cls = "colhl2";
        grid.append(el("div", { class: cls }, val));
      }
    }
    visual.append(el("div", { class: "detail-box" },
      el("p", { html: `Byte <code>${v}</code> at row ${r}, column ${c}: its first hex digit <b>${v[0]}</b> picks the <b>row</b> of the S-box and its second digit <b>${v[1]}</b> picks the <b>column</b>, giving <code>${s.after[r][c]}</code>.` }),
      grid));
    text.append(
      P("Every byte is replaced by another byte using a fixed 256-entry table, the <b>S-box</b>. All 16 bytes go through the same table independently."),
      formula("s'_{r,c} = S(s_{r,c})"),
      P("The S-box isn't arbitrary. For a byte <i>x</i> it takes the multiplicative inverse in the field GF(2<sup>8</sup>), then applies a fixed affine transformation:"),
      formula("S(x) = A \\cdot x^{-1} \\oplus \\texttt{63}"),
      P("In this project the table is <i>computed</i> from that definition rather than typed in (see <code>aes_core.py</code>)."),
      why("Why? This is the only <b>non-linear</b> step in AES. Without it, the whole cipher would be a system of linear equations that could be solved directly. It provides <i>confusion</i>."));
  }

  /* ShiftRows ------------------------------------------------------------------------------ */
  function stShift(s, visual, text) {
    const box = el("div", { class: "shift-anim" });
    const cells = [];
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) {
      const v = s.before[r][c], col = byteColor(v);
      const cell = el("div", { class: "cell", style: { background: col.bg, color: col.fg, left: `${8 + c * 48}px`, top: `${8 + r * 48}px` } }, v);
      box.append(cell);
      cells.push({ cell, r, c });
    }
    const labels = el("div", { class: "shift-rows-labels" },
      ["row 0: no shift", "row 1: ← 1", "row 2: ← 2", "row 3: ← 3"].map((t) => el("span", {}, t)));
    const animate = () => {
      cells.forEach(({ cell, r, c }) => {
        cell.style.transition = "none";
        cell.style.left = `${8 + c * 48}px`; cell.style.opacity = 1;
      });
      void box.offsetWidth;
      setTimeout(() => cells.forEach(({ cell, r, c }) => {
        const nc = (c - r + 4) % 4;
        if (c < r) {                       // byte wraps around to the right end
          cell.style.transition = "opacity .3s";
          cell.style.opacity = 0;
          setTimeout(() => { cell.style.transition = "none"; cell.style.left = `${8 + nc * 48}px`;
            void cell.offsetWidth; cell.style.transition = "opacity .4s"; cell.style.opacity = 1; }, 450);
        } else {
          cell.style.transition = "";
          cell.style.left = `${8 + nc * 48}px`;
        }
      }), 350);
    };
    visual.append(
      el("div", { class: "mat-row" },
        el("div", { class: "mat-wrap" }, el("div", { class: "mat-label" }, "watch the rows move"),
          el("div", { style: { display: "flex" } }, box, labels))),
      el("div", { style: { textAlign: "center" } }, el("button", { class: "btn small", onclick: animate }, "↻ replay animation")),
      el("div", { class: "mat-row" }, matrix(s.before, { label: "before", size: "small" }), opArrow(""), matrix(s.after, { label: "after ShiftRows", size: "small" })));
    animate();
    text.append(
      P("Each <b>row</b> of the state is rotated to the left: row 0 stays, row 1 moves 1 place, row 2 moves 2 places and row 3 moves 3 places. Bytes that fall off the left end come back on the right."),
      formula("s'_{r,c} = s_{r,\\,(c + r) \\bmod 4}"),
      P("Nothing is computed here; bytes only change position."),
      why("Why? Before ShiftRows, each column holds 4 bytes that will be mixed together. After it, the 4 bytes of every column come from <b>4 different columns</b>. Combined with MixColumns, after just two rounds every output byte depends on every input byte. This is <i>diffusion</i>."));
  }

  /* MixColumns ----------------------------------------------------------------------------- */
  function stMix(s, visual, text) {
    let [r, c] = sel;
    const pick = (rr, cc) => { sel = [rr, cc]; renderStage(); };
    visual.append(el("div", { class: "mat-row" },
      matrix(s.before, { label: `state (column ${c})`, col: c, onClick: pick, size: "mid" }),
      opArrow("× matrix"),
      matrix(s.after, { label: "after MixColumns", col: c, sel, onClick: pick, size: "mid" })));
    const m = s.mix[c];
    const M = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    const hl = (i, t) => (i === r ? `\\color{#993c1d}{${t}}` : t);
    const matTex = M.map((row, i) => row.map((v) => hl(i, `\\texttt{0${v}}`)).join(" & ")).join("\\\\");
    const inTex = m.in.map((v) => `\\texttt{${v}}`).join("\\\\");
    const outTex = m.out.map((v, i) => hl(i, `\\texttt{${v}}`)).join("\\\\");
    const row = m.rows[r];
    const prodTex = row.terms.map((t) => `\\texttt{0${t.coef}}\\bullet\\texttt{${t.byte}}`).join(" \\oplus ");
    const valTex = row.terms.map((t) => `\\texttt{${t.product}}`).join(" \\oplus ");
    visual.append(el("div", { class: "detail-box" },
      P(`Column ${c} is multiplied by a fixed matrix (click a byte on the right to choose the row):`),
      tex(`\\begin{bmatrix}${matTex}\\end{bmatrix}\\begin{bmatrix}${inTex}\\end{bmatrix} = \\begin{bmatrix}${outTex}\\end{bmatrix}`, true),
      P(`Output byte row ${r}:`),
      tex(`s'_{${r},${c}} = ${prodTex} = ${valTex} = \\texttt{${row.result}}`, true)));
    text.append(
      P("Each <b>column</b> is treated as a vector of 4 bytes and multiplied by a fixed 4 × 4 matrix. Every output byte depends on all four input bytes of its column."),
      formula("\\begin{bmatrix}s'_{0,c}\\\\s'_{1,c}\\\\s'_{2,c}\\\\s'_{3,c}\\end{bmatrix} = \\begin{bmatrix}02&03&01&01\\\\01&02&03&01\\\\01&01&02&03\\\\03&01&01&02\\end{bmatrix}\\begin{bmatrix}s_{0,c}\\\\s_{1,c}\\\\s_{2,c}\\\\s_{3,c}\\end{bmatrix}"),
      P("The arithmetic happens in GF(2<sup>8</sup>): addition is XOR (⊕) and multiplication (•) is polynomial multiplication modulo <i>x</i><sup>8</sup> + <i>x</i><sup>4</sup> + <i>x</i><sup>3</sup> + <i>x</i> + 1. In practice, <code>02•x</code> means shift <i>x</i> left by one bit and XOR with <code>1b</code> if a bit fell off, and <code>03•x = 02•x ⊕ x</code>."),
      why(`Why? A change in one input byte changes all four bytes of the column. This is the second half of AES's <i>diffusion</i>. The final round (round ${data.rounds} for AES-${data.keyBits}) skips MixColumns because it would add no security there.`));
  }

  return { init, load, run };
})();
