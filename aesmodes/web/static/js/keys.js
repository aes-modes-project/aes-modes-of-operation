/* keys.js - page 2: the AES-128 key schedule, word by word. */
"use strict";

App.pages.keys = (() => {
  let words = null;
  let sel = 4;

  function init() {
    bindKeyInput($("#keys-key"));
    $("#keys-run").addEventListener("click", run);
    $("#keys-key").addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  }

  async function run() {
    App.setKey($("#keys-key").value); syncKeyInputs();
    showError("keys-error", null);
    try { words = (await api("/api/keys", { key: App.state.key })).keyExpansion; }
    catch (err) { showError("keys-error", err); return; }
    renderGrid();
    renderDetail();
  }

  function renderGrid() {
    const g = $("#keys-grid");
    g.innerHTML = "";
    for (let r = 0; r < 11; r++) {
      g.append(el("div", { class: "rk", html: `<i>K</i><sub>${r}</sub>${r === 0 ? "&nbsp;(key)" : ""}` }));
      for (let j = 0; j < 4; j++) {
        const i = 4 * r + j, wd = words[i];
        let cls = "kw" + (wd.kind === "g" ? " g" : "");
        if (i === sel) cls += " sel";
        if (sel >= 4 && i === sel - 1) cls += " src1";
        if (sel >= 4 && i === sel - 4) cls += " src2";
        const box = el("div", { class: cls, title: `w${i}` }, wd.word, el("small", {}, `w${i}`));
        box.addEventListener("click", () => { sel = i; renderGrid(); renderDetail(); });
        g.append(box);
      }
    }
  }

  const wordCol = (hex, label, color) => el("div", { class: "wcol" },
    el("div", { class: "wl", html: label }),
    el("div", { class: "wbytes" }, hexBytes(hex).map((b) => {
      const c = color ? { bg: color[0], fg: color[1] } : byteColor(b);
      return el("div", { class: "cell", style: { background: c.bg, color: c.fg } }, b);
    })));
  const wop = (html) => el("div", { class: "wop", html: `<span class="ar">→</span>${html}` });
  const sym = (s) => el("div", { class: "op-symbol" }, s);

  function renderDetail() {
    const d = $("#keys-detail");
    d.innerHTML = "";
    const w = words[sel];
    d.append(el("h2", { html: `<span class="secnum">2.2</span>How <i>w</i><sub>${sel}</sub> is made` }));
    if (w.kind === "key") {
      d.append(el("p", { html: `The first four words are the key itself: <i>w</i><sub>${sel}</sub> is key bytes ${4 * sel} to ${4 * sel + 3}. Together, <i>w</i><sub>0</sub>…<i>w</i><sub>3</sub> form round key <i>K</i><sub>0</sub>.` }),
        el("div", { class: "word-chain" }, wordCol(w.word, `<i>w</i><sub>${sel}</sub>`)));
    } else if (w.kind === "xor") {
      d.append(el("p", { html: `Because ${sel} is not a multiple of 4, the rule is simple: XOR the previous word with the word four positions back.` }),
        tex(`w_{${sel}} = w_{${sel - 1}} \\oplus w_{${sel - 4}}`, true),
        el("div", { class: "word-chain" },
          wordCol(w.prev, `<i>w</i><sub>${sel - 1}</sub>`, ["#fbeaf0", "#993556"]), sym("⊕"),
          wordCol(w.back, `<i>w</i><sub>${sel - 4}</sub>`, ["#faeeda", "#854f0b"]), sym("="),
          wordCol(w.word, `<i>w</i><sub>${sel}</sub>`)));
    } else {
      const rc = sel / 4;
      d.append(el("p", { html: `${sel} is a multiple of 4, so this word starts a new round key (<i>K</i><sub>${rc}</sub>). The previous word first goes through the function <i>g</i>:` }),
        tex(`w_{${sel}} = w_{${sel - 4}} \\oplus g(w_{${sel - 1}}), \\quad g(w) = \\mathrm{SubWord}(\\mathrm{RotWord}(w)) \\oplus \\mathrm{Rcon}_{${rc}}`, true),
        el("div", { class: "word-chain" },
          wordCol(w.prev, `<i>w</i><sub>${sel - 1}</sub>`, ["#fbeaf0", "#993556"]),
          wop("RotWord"), wordCol(w.rot, "rotated"),
          wop("SubWord"), wordCol(w.sub, "S-box"),
          el("div", { class: "op-symbol" }, "⊕"), wordCol(w.rcon, `Rcon<sub>${rc}</sub>`, ["#e6f1fb", "#185fa5"]),
          el("div", { class: "op-symbol" }, "="), wordCol(w.temp, `<i>g</i>(<i>w</i><sub>${sel - 1}</sub>)`)),
        el("div", { class: "word-chain" },
          wordCol(w.temp, `<i>g</i>(<i>w</i><sub>${sel - 1}</sub>)`), sym("⊕"),
          wordCol(w.back, `<i>w</i><sub>${sel - 4}</sub>`, ["#faeeda", "#854f0b"]), sym("="),
          wordCol(w.word, `<i>w</i><sub>${sel}</sub>`)),
        el("ul", {},
          el("li", { html: "<b>RotWord</b> moves the bytes up by one: [a<sub>0</sub>, a<sub>1</sub>, a<sub>2</sub>, a<sub>3</sub>] → [a<sub>1</sub>, a<sub>2</sub>, a<sub>3</sub>, a<sub>0</sub>]." }),
          el("li", { html: "<b>SubWord</b> passes each byte through the same S-box used by SubBytes." }),
          el("li", { html: `<b>Rcon</b> (round constant) XORs the first byte with <i>x</i><sup>${rc - 1}</sup> in GF(2<sup>8</sup>): <code>01 02 04 08 10 20 40 80 1b 36</code>. This makes every round key different, even for a key made of identical bytes.` })));
    }
    d.append(el("p", { class: "why", html: "Why so complicated? If round keys were simple copies of the key, related-key and slide attacks would become possible. SubWord adds non-linearity and Rcon breaks symmetry between rounds." }));
  }

  return { init, run };
})();
