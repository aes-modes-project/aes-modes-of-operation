/* modes.js - page 3: the five modes of operation, block by block. */
"use strict";

App.pages.modes = (() => {
  const INFO = {
    ECB: {
      name: "Electronic Codebook", tag: "each block on its own",
      what: "The padded message is cut into 16-byte blocks and <b>every block is encrypted separately</b> with the same key. There is no IV and no chaining.",
      enc: "C_i = E_K(P_i)", dec: "P_i = D_K(C_i)",
      why: "It's simple and parallel, but <b>identical plaintext blocks give identical ciphertext blocks</b>, so patterns in the data stay visible. That's why ECB should never be used for messages (see Experiment 4.1).",
      props: [["Needs AES decryption", true], ["Parallel encryption", true], ["Parallel decryption", true], ["Hides patterns", false]],
      err: "1 flipped bit garbles that whole block only",
    },
    CBC: {
      name: "Cipher Block Chaining", tag: "XOR with the previous ciphertext",
      what: "Before encryption, each plaintext block is <b>XORed with the previous ciphertext block</b>. The first block uses the IV, which is all zeros here as the specification requires.",
      enc: "C_i = E_K(P_i \\oplus C_{i-1}),\\quad C_0 = IV", dec: "P_i = D_K(C_i) \\oplus C_{i-1}",
      why: "Chaining makes each ciphertext block depend on <b>all previous plaintext blocks</b>, so repeated blocks no longer look the same. Encryption must run in order; decryption can run in parallel.",
      props: [["Needs AES decryption", true], ["Parallel encryption", false], ["Parallel decryption", true], ["Hides patterns", true]],
      err: "garbles that block and flips the same bit in the next one",
    },
    CFB: {
      name: "Cipher Feedback", tag: "encrypt the previous ciphertext",
      what: "AES encrypts the <b>previous ciphertext block</b> (the zero IV for the first block), and the result is XORed with the plaintext. This turns the block cipher into a <b>self-synchronising stream cipher</b>. Here the full-block variant (CFB-128) is used.",
      enc: "C_i = P_i \\oplus E_K(C_{i-1}),\\quad C_0 = IV", dec: "P_i = C_i \\oplus E_K(C_{i-1})",
      why: "Notice that <b>decryption also uses AES encryption</b>: the receiver recomputes the same E<sub>K</sub>(C<sub>i−1</sub>). The inverse cipher is never needed.",
      props: [["Needs AES decryption", false], ["Parallel encryption", false], ["Parallel decryption", true], ["Hides patterns", true]],
      err: "flips the same bit, then garbles the next block",
    },
    OFB: {
      name: "Output Feedback", tag: "keystream from repeated encryption",
      what: "AES keeps encrypting its <b>own previous output</b>, starting from the IV: O<sub>1</sub> = E<sub>K</sub>(IV), O<sub>2</sub> = E<sub>K</sub>(O<sub>1</sub>), … This keystream is XORed with the message.",
      enc: "O_i = E_K(O_{i-1}),\\ O_0 = IV,\\quad C_i = P_i \\oplus O_i", dec: "P_i = C_i \\oplus O_i",
      why: "The keystream <b>doesn't depend on the message</b>, so it can be computed in advance and bit errors don't spread. But reusing the same IV with the same key reuses the keystream, which with the zero IV happens for every message.",
      props: [["Needs AES decryption", false], ["Parallel encryption", false], ["Keystream precomputable", true], ["Hides patterns", true]],
      err: "only the flipped bit is wrong",
    },
    CTR: {
      name: "Counter", tag: "encrypt a counter",
      what: "AES encrypts a sequence of <b>counter values</b> T<sub>1</sub>, T<sub>1</sub>+1, T<sub>1</sub>+2, … and the result is XORed with the message. As the specification requires, <b>you choose the initial counter</b> T<sub>1</sub>.",
      enc: "C_i = P_i \\oplus E_K(T_i),\\quad T_i = T_1 + i - 1 \\pmod{2^{128}}", dec: "P_i = C_i \\oplus E_K(T_i)",
      why: "Every block is independent, so CTR is <b>fully parallel</b> and allows random access to any block. This is why it's the basis of modern AES-GCM. The receiver must use the same initial counter.",
      props: [["Needs AES decryption", false], ["Parallel encryption", true], ["Parallel decryption", true], ["Hides patterns", true]],
      err: "only the flipped bit is wrong",
    },
  };
  const MODES = Object.keys(INFO);

  let mode = "CBC";
  let op, fmt, result = null, selBlock = 0;

  /* ---------------------------------------------------------------- setup */
  function init() {
    bindKeyInput($("#mode-key"));
    $("#mode-data").value = "Hello, AES modes! This message is longer than one block.";
    op = segmented("mode-op", onOpChange);
    fmt = segmented("mode-fmt");
    const tabs = $("#mode-tabs");
    MODES.forEach((m) => {
      const b = el("button", { class: "mode-tab", style: { "--c": `var(--${m})` } }, el("b", {}, m), el("span", {}, INFO[m].tag));
      b.dataset.m = m;
      b.addEventListener("click", () => { setMode(m); run(); });
      tabs.append(b);
    });
    $("#mode-run").addEventListener("click", run);
    ["#mode-data", "#mode-key", "#mode-ctr"].forEach((s) => $(s).addEventListener("keydown", (e) => { if (e.key === "Enter") run(); }));
    setMode(mode);
  }

  function setMode(m) {
    mode = m;
    $$(".mode-tab").forEach((b) => {
      const on = b.dataset.m === m;
      b.classList.toggle("on", on);
      b.style.background = on ? `var(--${b.dataset.m})` : "";
      b.style.borderColor = on ? `var(--${b.dataset.m})` : "";
    });
    $("#mode-iv-field").hidden = m === "ECB" || m === "CTR";
    $("#mode-ctr-field").hidden = m !== "CTR";
    renderExplain();
  }

  function onOpChange(v) {
    const dec = v === "decrypt";
    $("#mode-data-label").textContent = dec ? "Ciphertext (hex)" : "Message";
    $("#mode-fmt").style.visibility = dec ? "hidden" : "visible";
    if (dec && result && result.operation === "encrypt") $("#mode-data").value = result.output;
    $("#mode-data").classList.toggle("mono", dec);
    renderExplain();
  }

  async function run() {
    App.setKey($("#mode-key").value); syncKeyInputs();
    showError("mode-error", null);
    try {
      result = await api("/api/mode", {
        mode, operation: op.get(), key: App.state.key, data: $("#mode-data").value,
        dataFormat: fmt.get(), counter: mode === "CTR" ? $("#mode-ctr").value : null,
      });
    } catch (err) { showError("mode-error", err); return; }
    selBlock = 0;
    renderExplain(); renderPadding(); renderChain(); renderDetail(); renderResult();
  }

  /* ---------------------------------------------------------------- explanation */
  function renderExplain() {
    const i = INFO[mode], box = $("#mode-explain");
    box.innerHTML = "";
    box.append(
      el("h2", { html: `<span class="secnum">3.1</span><span class="mode-chip m-${mode}" style="font-size:16px">${mode}</span> ${i.name}` }),
      el("p", { html: i.what }),
      el("div", { class: "formula", style: { background: "#f8f6f0", borderRadius: "6px", padding: "8px 12px", margin: "8px 0" } },
        el("div", {}, el("span", { class: "muted", style: { fontSize: "14px" } }, "encryption "), tex(i.enc)),
        el("div", {}, el("span", { class: "muted", style: { fontSize: "14px" } }, "decryption "), tex(i.dec))),
      el("p", { class: "why", html: i.why }),
      el("div", { class: "props" },
        i.props.map(([t, yes]) => el("span", { class: "prop " + (yes ? "yes" : "no") }, (yes ? "✓ " : "✗ ") + t)),
        el("span", { class: "prop info" }, "bit error: " + i.err)));
  }

  /* ---------------------------------------------------------------- padding */
  function renderPadding() {
    const box = $("#mode-padding");
    box.innerHTML = "";
    const r = result;
    const bytes = hexBytes(r.padded);
    const msgLen = r.messageLength, pc = r.padCount;
    box.append(el("h2", { html: `<span class="secnum">3.2</span>Padding the last block` }),
      el("p", { html: r.operation === "encrypt"
        ? `The message is <b>${msgLen} bytes</b>. To fill whole 16-byte blocks, <b>${pc} bytes</b> were added: ${pc - 1} zero bytes and a final byte holding the count, <code>${pc.toString(16).padStart(2, "0")}</code> = ${pc}.${msgLen % 16 === 0 ? " Because the message was already a multiple of 16 bytes, a whole extra block was added, so the receiver can always read the last byte as the pad count." : ""}`
        : `After decryption, the last byte is <code>${pc.toString(16).padStart(2, "0")}</code> = ${pc}, so the last ${pc} bytes are padding and were removed, leaving <b>${msgLen} bytes</b>.` }));
    const grid = el("div", { class: "pad-grid" });
    bytes.forEach((b, k) => {
      if (k % 16 === 0) grid.append(el("div", { class: "bl" }, `block ${k / 16 + 1}`));
      const isPad = k >= bytes.length - pc;
      const isCount = k === bytes.length - 1;
      const ch = String.fromCharCode(parseInt(b, 16));
      const printable = !isPad && /[\x20-\x7e]/.test(ch);
      grid.append(el("div", { class: "pb " + (isCount ? "count" : isPad ? "zero" : "msg"), title: `byte ${k}` },
        b, el("small", {}, isCount ? "count" : printable ? ch : "")));
    });
    box.append(grid, el("div", { class: "pad-legend", html:
      '<span><i style="background:var(--key-bg)"></i>message</span><span><i style="background:#efede6"></i>zero padding</span><span><i style="background:var(--ark)"></i>pad count</span>' }));
  }

  /* ---------------------------------------------------------------- chain diagram (SVG) */
  const SUBS = "₀₁₂₃₄₅₆₇₈₉";
  const sub = (n) => String(n).split("").map((d) => SUBS[+d]).join("");
  const NS = "http://www.w3.org/2000/svg";
  const svgEl = (tag, attrs = {}, text) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const COLW = 300, BW = 130, BH = 46, LX = 85, RX = 225;

  function renderChain() {
    const wrap = $("#mode-chain");
    wrap.innerHTML = "";
    const steps = result.steps.slice(0, 12);
    const dec = result.operation === "decrypt";
    const stream = ["CFB", "OFB", "CTR"].includes(mode);
    const H = stream ? 420 : 300;
    const W = steps.length * COLW + 10;
    const svg = svgEl("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}` });
    svg.style.setProperty("--modecolor", getComputedStyle(document.documentElement).getPropertyValue(`--${mode}`));
    const defs = svgEl("defs");
    defs.innerHTML = `<marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#8f8b7e"/></marker>
      <marker id="ahc" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--${mode})"/></marker>`;
    svg.append(defs);

    const box = (g, x, y, label, value, cls = "") => {
      const n = svgEl("g", { class: "node " + cls });
      n.append(svgEl("rect", { x: x - BW / 2, y, width: BW, height: BH, rx: 6 }),
        svgEl("text", { x, y: y + 17, "text-anchor": "middle", class: "lbl" }, label),
        svgEl("text", { x, y: y + 35, "text-anchor": "middle", class: "val" }, shortHex(value)));
      const t = svgEl("title", {}, `${label}: ${groupHex(value)}`);
      n.append(t);
      g.append(n);
    };
    const aes = (g, x, y, decrypt) => {
      const n = svgEl("g", { class: "node aes" });
      n.append(svgEl("rect", { x: x - 55, y, width: 110, height: 38, rx: 6 }));
      const t = svgEl("text", { x, y: y + 25, "text-anchor": "middle", class: "aesname" });
      t.innerHTML = `${decrypt ? "D" : "E"}<tspan dy="4" font-size="11">K</tspan><tspan dy="-4" font-size="12"> (AES)</tspan>`;
      n.append(t);
      g.append(n);
    };
    const xor = (g, x, y) => {
      const n = svgEl("g", { class: "xor" });
      n.append(svgEl("circle", { cx: x, cy: y, r: 12 }), svgEl("path", { d: `M${x - 7},${y} H${x + 7} M${x},${y - 7} V${y + 7}` }));
      g.append(n);
    };
    const edge = (g, d, chain = false) => g.append(svgEl("path", { d, class: "edge" + (chain ? " chain" : ""), "marker-end": `url(#${chain ? "ahc" : "ah"})` }));
    const note = (g, x, y, text, anchor = "start") => g.append(svgEl("text", { x, y, class: "small", "text-anchor": anchor }, text));

    steps.forEach((s, k) => {
      const i = k + 1, X = k * COLW;
      const g = svgEl("g", { class: "col" + (k === selBlock ? " sel" : ""), transform: `translate(${X},0)` });
      g.append(svgEl("rect", { class: "bg", x: 4, y: 0, width: COLW - 8, height: H, rx: 8 }));
      g.append(svgEl("text", { x: COLW / 2, y: 16, "text-anchor": "middle", class: "colhead" }, `block ${i}`));
      const P = dec ? "C" : "P", Q = dec ? "P" : "C";
      if (mode === "ECB") {
        box(g, RX, 30, `${P}${sub(i)}`, s.blockIn);
        edge(g, `M${RX},76 V118`);
        aes(g, RX, 120, dec);
        edge(g, `M${RX},158 V198`);
        box(g, RX, 200, `${Q}${sub(i)}`, s.blockOut, "out");
      } else if (mode === "CBC" && !dec) {
        box(g, RX, 30, `P${sub(i)}`, s.blockIn);
        edge(g, `M${RX},76 V96`);
        xor(g, RX, 110);
        edge(g, `M${RX},122 V148`);
        note(g, RX - 14, 140, shortHex(s.aesInput), "end");
        aes(g, RX, 150, false);
        edge(g, `M${RX},188 V226`);
        box(g, RX, 228, `C${sub(i)}`, s.blockOut, "out");
        if (i === 1) { box(g, LX, 87, "IV = C₀", s.xorWith, "feed"); edge(g, `M${LX + BW / 2},110 H${RX - 14}`, true); }
      } else if (mode === "CBC" && dec) {
        box(g, RX, 30, `C${sub(i)}`, s.blockIn);
        edge(g, `M${RX},76 V108`);
        aes(g, RX, 110, true);
        edge(g, `M${RX},148 V186`);
        note(g, RX - 14, 168, shortHex(s.aesOutput), "end");
        xor(g, RX, 200);
        edge(g, `M${RX},212 V248`);
        box(g, RX, 250, `P${sub(i)}`, s.blockOut, "out");
        if (i === 1) { box(g, LX, 177, "IV = C₀", s.xorWith, "feed"); edge(g, `M${LX + BW / 2},200 H${RX - 14}`, true); }
      } else {
        const inLabel = { CFB: i === 1 ? "IV = C₀" : `C${sub(i - 1)}`, OFB: i === 1 ? "IV = O₀" : `O${sub(i - 1)}`, CTR: `T${sub(i)} (counter)` }[mode];
        const ksLabel = { CFB: `E(C${sub(i - 1)})`, OFB: `O${sub(i)}`, CTR: `E(T${sub(i)})` }[mode];
        box(g, RX, 30, inLabel, s.aesInput, mode === "CTR" ? "" : "feed");
        edge(g, `M${RX},76 V108`);
        aes(g, RX, 110, false);
        edge(g, `M${RX},148 V178`);
        box(g, RX, 180, ksLabel, s.aesOutput);
        edge(g, `M${RX},226 V261`);
        xor(g, RX, 275);
        box(g, LX, 252, `${P}${sub(i)}`, s.blockIn);
        edge(g, `M${LX + BW / 2},275 H${RX - 14}`);
        edge(g, `M${RX},287 V318`);
        box(g, RX, 320, `${Q}${sub(i)}`, s.blockOut, "out");
      }
      g.addEventListener("click", () => { selBlock = k; renderChain(); renderDetail(); });
      svg.append(g);
    });

    // connections between neighbouring blocks
    for (let k = 1; k < steps.length; k++) {
      const X = k * COLW, pX = (k - 1) * COLW, gap = X + 10;
      const g = svgEl("g");
      if (mode === "CBC" && !dec) edge(g, `M${pX + RX + BW / 2},251 H${gap} V110 H${X + RX - 14}`, true);
      if (mode === "CBC" && dec) edge(g, `M${pX + RX + BW / 2},53 H${gap} V200 H${X + RX - 14}`, true);
      if (mode === "CFB" && !dec) edge(g, `M${pX + RX + BW / 2},343 H${gap} V53 H${X + RX - BW / 2}`, true);
      if (mode === "CFB" && dec) edge(g, `M${pX + LX},298 V400 H${gap} V53 H${X + RX - BW / 2}`, true);
      if (mode === "OFB") edge(g, `M${pX + RX + BW / 2},203 H${gap} V53 H${X + RX - BW / 2}`, true);
      if (mode === "CTR") {
        edge(g, `M${pX + RX + BW / 2},53 H${X + RX - BW / 2}`, true);
        g.append(svgEl("text", { x: gap + 20, y: 46, class: "small" }, "+1"));
      }
      svg.append(g);
    }
    wrap.append(svg);
    if (result.steps.length > 12) wrap.append(el("p", { class: "muted" }, `Showing the first 12 of ${result.steps.length} blocks.`));
  }

  /* ---------------------------------------------------------------- one block in detail */
  function renderDetail() {
    const d = $("#mode-block-detail");
    d.innerHTML = "";
    const s = result.steps[selBlock];
    if (!s) return;
    const i = s.index, dec = result.operation === "decrypt";
    const T = (h) => `\\texttt{${shortHex(h)}}`;
    let f;
    const P = dec ? "C" : "P", Q = dec ? "P" : "C";
    if (mode === "ECB") f = `${Q}_{${i}} = ${dec ? "D" : "E"}_K(${P}_{${i}}) = ${dec ? "D" : "E"}_K(${T(s.blockIn)}) = ${T(s.blockOut)}`;
    else if (mode === "CBC" && !dec) f = `C_{${i}} = E_K(P_{${i}} \\oplus C_{${i - 1}}) = E_K(${T(s.blockIn)} \\oplus ${T(s.xorWith)}) = E_K(${T(s.aesInput)}) = ${T(s.blockOut)}`;
    else if (mode === "CBC") f = `P_{${i}} = D_K(C_{${i}}) \\oplus C_{${i - 1}} = ${T(s.aesOutput)} \\oplus ${T(s.xorWith)} = ${T(s.blockOut)}`;
    else f = `${Q}_{${i}} = ${P}_{${i}} \\oplus E_K(${T(s.aesInput)}) = ${T(s.blockIn)} \\oplus ${T(s.aesOutput)} = ${T(s.blockOut)}`;
    const rows = [
      [dec ? "input (ciphertext)" : "input (plaintext)", s.blockIn],
      ["into AES", s.aesInput],
      ["out of AES", s.aesOutput],
      s.xorWith && mode !== "ECB" ? ["XORed with", s.xorWith] : null,
      [dec ? "output (plaintext)" : "output (ciphertext)", s.blockOut],
    ].filter(Boolean);
    const canOpen = !(mode === "ECB" && dec) && !(mode === "CBC" && dec);
    d.append(
      el("h3", { html: `Block ${i}` }),
      el("div", { style: { overflowX: "auto" } }, tex(f, true)),
      el("table", {}, rows.map(([k, v]) => el("tr", {}, el("td", {}, k), el("td", {}, el("code", {}, groupHex(v)))))),
      canOpen ? el("p", { style: { marginTop: "10px" } }, el("button", { class: "btn small", onclick: () => App.pages.aes.load(App.state.key, s.aesInput) },
        `Open block ${i}'s AES encryption step by step →`)) : el("p", { class: "muted", style: { marginTop: "8px" } },
        "This mode uses AES decryption (the inverse cipher) here. The step-by-step page shows encryption."));
  }

  /* ---------------------------------------------------------------- result */
  function renderResult() {
    const r = result, box = $("#mode-result");
    box.innerHTML = "";
    const dec = r.operation === "decrypt";
    const rows = [
      ["mode", `${r.mode}${r.iv ? " (IV = 00…00)" : ""}${r.counter ? ` (T₁ = ${r.counter})` : ""}`],
      [dec ? "plaintext (hex)" : "ciphertext (hex)", groupHex(r.output)],
      dec ? ["plaintext (text)", r.outputText === null ? "(not valid UTF-8 text)" : r.outputText] : null,
      ["length", `${r.output.length / 2} bytes${dec ? "" : ` (${r.messageLength} message + ${r.padCount} padding)`}`],
    ].filter(Boolean);
    const copy = el("button", { class: "btn small", onclick: (e) => {
      navigator.clipboard && navigator.clipboard.writeText(r.output);
      e.target.textContent = "Copied"; setTimeout(() => (e.target.textContent = "Copy hex"), 1200);
    } }, "Copy hex");
    const flip = el("button", { class: "btn small primary", onclick: () => {
      op.set(dec ? "encrypt" : "decrypt");
      $("#mode-data").value = dec ? (r.outputText ?? r.output) : r.output;
      if (dec && r.outputText === null) fmt.set("hex"); else if (dec) fmt.set("text");
      onOpChange(op.get()); run();
    } }, dec ? "Encrypt it again →" : "Decrypt this ciphertext →");
    box.append(el("h2", { html: `<span class="secnum">3.4</span>Result` }),
      el("div", { class: "result-box" }, rows.flatMap(([k, v]) => [el("div", { class: "k" }, k),
        el("div", { class: "v" + (k === "plaintext (text)" ? " text" : "") }, v)])),
      el("p", { style: { marginTop: "12px", display: "flex", gap: "8px" } }, copy, flip));
  }

  return { init, run, INFO };
})();
