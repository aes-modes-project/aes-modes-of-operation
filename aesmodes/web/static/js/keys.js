/* keys.js - page 2: the AES key schedule (128-, 192- and 256-bit keys), word by word. */
"use strict";

App.pages.keys = (() => {
  let words = null;
  let sel = 4;

  function init() {
    bindKeyInput($("#keys-key"), () => run());
    $("#keys-run").addEventListener("click", run);
    $("#keys-key").addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  }

  async function run() {
    App.setKey($("#keys-key").value); syncKeyInputs();
    showError("keys-error", null);
    try { words = (await api("/api/keys", { key: App.state.key })).keyExpansion; }
    catch (err) { showError("keys-error", err); return; }
    const nk = words[0].nk;
    if (sel >= words.length || sel < nk) sel = nk;      // first computed word
    renderLead();
    renderGrid();
    renderDetail();
  }

  function renderLead() {
    const nk = words[0].nk, n = words.length, nr = n / 4 - 1, bits = nk * 32;
    $("#keys-count").textContent = n;
    $("#keys-lead").innerHTML =
      `AES-${bits} runs ${nr} rounds, so it needs <b>${nr + 1} round keys</b>: one before the first round plus one per round. ` +
      `The key schedule stretches the ${nk * 4}-byte key (<i>N</i><sub>k</sub> = ${nk} words) into <b>${n} four-byte words</b> ` +
      `<i>w</i><sub>0</sub>…<i>w</i><sub>${n - 1}</sub>; round key <i>r</i> is <i>w</i><sub>4r</sub>…<i>w</i><sub>4r+3</sub>.` +
      (nk === 6 ? " With AES-192 the key is 6 words long, so the key itself spans round key 0 and half of round key 1." : "") +
      (nk === 8 ? " With AES-256 the key is 8 words long and fills round keys 0 and 1; an extra SubWord step is added halfway through each group of 8 words." : "");
  }

  function renderGrid() {
    const g = $("#keys-grid");
    g.innerHTML = "";
    const nk = words[0].nk;
    for (let r = 0; r < words.length / 4; r++) {
      g.append(el("div", { class: "rk", html: `<i>K</i><sub>${r}</sub>` }));
      for (let j = 0; j < 4; j++) {
        const i = 4 * r + j, wd = words[i];
        let cls = "kw" + (wd.kind === "g" ? " g" : wd.kind === "h" ? " h" : "");
        if (i === sel) cls += " sel";
        if (sel >= nk && i === sel - 1) cls += " src1";
        if (sel >= nk && i === sel - nk) cls += " src2";
        const box = el("div", { class: cls, title: `w${i}` }, wd.word,
          el("small", {}, wd.kind === "key" ? `w${i} · key` : `w${i}`));
        box.addEventListener("click", () => { sel = i; renderGrid(); renderDetail(); });
        g.append(box);
      }
    }
    if (!$("#keys-legend")) g.after(el("p", { id: "keys-legend", class: "pad-legend", style: { marginTop: "10px" }, html:
        '<span><i style="background:#f6f4ee;border:1px solid #dcd8cc"></i>XOR only</span>' +
        '<span><i style="background:var(--key-bg)"></i>uses RotWord, SubWord, Rcon</span>' +
        '<span><i style="background:var(--sub-bg)"></i>AES-256 extra SubWord</span>' +
        '<span><i style="background:var(--xor-bg)"></i>previous word</span>' +
        '<span><i style="background:var(--ark-bg)"></i>word N<sub>k</sub> back</span>' }));
  }

  const wordCol = (hex, label, color) => el("div", { class: "wcol" },
    el("div", { class: "wl", html: label }),
    el("div", { class: "wbytes" }, hexBytes(hex).map((b) => {
      const c = color ? { bg: color[0], fg: color[1] } : byteColor(b);
      return el("div", { class: "cell", style: { background: c.bg, color: c.fg } }, b);
    })));
  const wop = (html) => el("div", { class: "wop", html: `<span class="ar">→</span>${html}` });
  const sym = (s) => el("div", { class: "op-symbol" }, s);
  const PREV = ["#fbeaf0", "#993556"], BACK = ["#faeeda", "#854f0b"];

  function renderDetail() {
    const d = $("#keys-detail");
    d.innerHTML = "";
    const w = words[sel], nk = w.nk, bits = nk * 32;
    const W = (i) => `<i>w</i><sub>${i}</sub>`;
    d.append(el("h2", { html: `<span class="secnum">2.2</span>How ${W(sel)} is made <span class="size-badge">AES-${bits}</span>` }));
    if (w.kind === "key") {
      d.append(el("p", { html: `The first ${nk} words are the key itself: ${W(sel)} is key bytes ${4 * sel} to ${4 * sel + 3}.` }),
        el("div", { class: "word-chain" }, wordCol(w.word, W(sel))));
    } else if (w.kind === "xor") {
      d.append(el("p", { html: `Because ${sel} is not a multiple of <i>N</i><sub>k</sub> = ${nk}${nk === 8 ? " (and not 4 more than one)" : ""}, the rule is simple: XOR the previous word with the word ${nk} positions back.` }),
        tex(`w_{${sel}} = w_{${sel - 1}} \\oplus w_{${sel - nk}}`, true),
        el("div", { class: "word-chain" },
          wordCol(w.prev, W(sel - 1), PREV), sym("⊕"), wordCol(w.back, W(sel - nk), BACK), sym("="), wordCol(w.word, W(sel))));
    } else if (w.kind === "h") {
      d.append(el("p", { html: `This step exists <b>only in AES-256</b>. Because the key is 8 words long, every 8-word group gets an extra non-linear step in the middle: when <i>i</i> mod 8 = 4, the previous word goes through <b>SubWord</b> (the S-box on each byte) before the XOR. There is no RotWord and no Rcon here.` }),
        tex(`w_{${sel}} = w_{${sel - 8}} \\oplus \\mathrm{SubWord}(w_{${sel - 1}})`, true),
        el("div", { class: "word-chain" },
          wordCol(w.prev, W(sel - 1), PREV), wop("SubWord"), wordCol(w.sub, "S-box"),
          sym("⊕"), wordCol(w.back, W(sel - 8), BACK), sym("="), wordCol(w.word, W(sel))));
    } else {
      const rc = w.rcon_index;
      d.append(el("p", { html: `${sel} is a multiple of <i>N</i><sub>k</sub> = ${nk}, so the previous word first goes through the function <i>g</i>:` }),
        tex(`w_{${sel}} = w_{${sel - nk}} \\oplus g(w_{${sel - 1}}), \\quad g(w) = \\mathrm{SubWord}(\\mathrm{RotWord}(w)) \\oplus \\mathrm{Rcon}_{${rc}}`, true),
        el("div", { class: "word-chain" },
          wordCol(w.prev, W(sel - 1), PREV),
          wop("RotWord"), wordCol(w.rot, "rotated"),
          wop("SubWord"), wordCol(w.sub, "S-box"),
          sym("⊕"), wordCol(w.rcon, `Rcon<sub>${rc}</sub>`, ["#e6f1fb", "#185fa5"]),
          sym("="), wordCol(w.temp, `<i>g</i>(${W(sel - 1)})`)),
        el("div", { class: "word-chain" },
          wordCol(w.temp, `<i>g</i>(${W(sel - 1)})`), sym("⊕"), wordCol(w.back, W(sel - nk), BACK), sym("="), wordCol(w.word, W(sel))),
        el("ul", {},
          el("li", { html: "<b>RotWord</b> moves the bytes up by one: [a<sub>0</sub>, a<sub>1</sub>, a<sub>2</sub>, a<sub>3</sub>] → [a<sub>1</sub>, a<sub>2</sub>, a<sub>3</sub>, a<sub>0</sub>]." }),
          el("li", { html: "<b>SubWord</b> passes each byte through the same S-box used by SubBytes." }),
          el("li", { html: `<b>Rcon</b> (round constant) XORs the first byte with <i>x</i><sup>${rc - 1}</sup> in GF(2<sup>8</sup>): <code>01 02 04 08 10 20 40 80 1b 36</code>. AES-${bits} uses the first ${Math.ceil((words.length - nk) / nk)} of them.` })));
    }
    d.append(el("p", { class: "why", html: "Why so complicated? If round keys were simple copies of the key, related-key and slide attacks would become possible. SubWord adds non-linearity and Rcon breaks the symmetry between rounds. AES-256's extra SubWord keeps the longer key schedule from being too linear." }));
  }

  return { init, run };
})();
