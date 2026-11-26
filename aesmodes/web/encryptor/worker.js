/* worker.js - runs the project's Python encryptor (aesmodes/filecrypt.py) with Pyodide
   in a background thread, so the page stays responsive while large files are processed.

   Messages in:  {id, cmd: "encryptFile"|"encryptText"|"decryptFile"|"decryptText"|"inspect", ...}
   Messages out: {type: "ready"} | {type: "status", text} | {type: "progress", id, done, total}
                 {type: "result", id, meta, data?} | {type: "error", id, message}               */
"use strict";

const PYODIDE_BASE = new URL("../static/vendor/pyodide/", self.location).href;
const PY_BASE = new URL("../py/aesmodes/", self.location).href;
const PY_FILES = ["__init__.py", "aes_core.py", "padding.py", "modes.py", "fastaes.py", "filecrypt.py"];

let py = null;

const ready = (async () => {
  postMessage({ type: "status", text: "Downloading the Python runtime…" });
  importScripts(PYODIDE_BASE + "pyodide.js");
  py = await loadPyodide({ indexURL: PYODIDE_BASE });
  postMessage({ type: "status", text: "Loading the project's AES code…" });
  py.FS.mkdirTree("/home/pyodide/aesmodes");
  for (const f of PY_FILES) {
    const r = await fetch(PY_BASE + f, { cache: "no-cache" });
    if (!r.ok) throw new Error(`Could not load ${f}`);
    py.FS.writeFile(`/home/pyodide/aesmodes/${f}`, await r.text());
  }
  py.runPython(`
import json, sys, time
sys.path.insert(0, "/home/pyodide")
from aesmodes import filecrypt as fc

def _info(info):
    return {k: (v.hex() if isinstance(v, bytes) else v) for k, v in info.items()}

def _key_args(o):
    if o.get("keyType") == "hex":
        return {"hex_key": o.get("hexKey", "")}
    return {"password": o.get("password", "")}

def _enc_args(o):
    a = {"mode": o["mode"], "key_bits": int(o.get("bits", 256)), "name": o.get("name", "")}
    a.update(_key_args(o))
    if o["mode"] == "CTR":
        if o.get("randomIv"):
            a["random_iv"] = True
        else:
            a["counter"] = o.get("counter") or "0"
    elif o.get("randomIv"):
        a["random_iv"] = True
    return a

def run(cmd, opts_json, data, progress):
    o = json.loads(opts_json)
    t0 = time.perf_counter()
    try:
        if cmd == "encryptFile":
            blob = fc.encrypt_container(bytes(data.to_py()), progress=progress, **_enc_args(o))
            meta = _info(fc.read_header(blob)); meta["outBytes"] = len(blob)
            out = blob
        elif cmd == "encryptText":
            token = fc.encrypt_text(o["text"], progress=progress, **_enc_args(o))
            meta = {"token": token}
            out = None
        elif cmd == "decryptFile":
            plain, info = fc.decrypt_container(bytes(data.to_py()), progress=progress, **_key_args(o))
            meta = _info(info); meta["outBytes"] = len(plain)
            out = plain
        elif cmd == "decryptText":
            text, info = fc.decrypt_text(o["token"], progress=progress, **_key_args(o))
            meta = _info(info); meta["text"] = text
            out = None
        elif cmd == "inspect":
            if data is not None:
                meta = _info(fc.read_header(bytes(data.to_py())))
            else:
                import base64
                t = "".join(o["token"].split())
                if not t.startswith(fc.TEXT_PREFIX):
                    raise ValueError("An encrypted message starts with " + fc.TEXT_PREFIX)
                meta = _info(fc.read_header(base64.b64decode(t[len(fc.TEXT_PREFIX):])))
            out = None
        else:
            raise ValueError("unknown command " + cmd)
        meta["seconds"] = round(time.perf_counter() - t0, 3)
        return json.dumps({"ok": True, "meta": meta}), out
    except ValueError as e:
        return json.dumps({"ok": False, "error": str(e)}), None
`);
  postMessage({ type: "ready" });
})().catch((e) => postMessage({ type: "fatal", message: String(e.message || e) }));

self.onmessage = async (ev) => {
  const { id, cmd, opts, data } = ev.data;
  try {
    await ready;
    let last = 0;
    const progress = (done, total) => {
      const now = Date.now();
      if (now - last > 80 || done === total) { last = now; postMessage({ type: "progress", id, done, total }); }
    };
    const res = py.globals.get("run")(cmd, JSON.stringify(opts || {}), data || undefined, progress);
    const status = JSON.parse(res.get(0));
    const outProxy = res.get(1);
    let out = null;
    if (outProxy !== undefined && outProxy !== null) {
      out = outProxy.toJs();
      if (outProxy.destroy) outProxy.destroy();
    }
    res.destroy();
    if (!status.ok) { postMessage({ type: "error", id, message: status.error }); return; }
    postMessage({ type: "result", id, meta: status.meta, data: out }, out ? [out.buffer] : []);
  } catch (e) {
    const msg = String(e.message || e).trim().split("\n").filter(Boolean).pop();
    postMessage({ type: "error", id, message: msg || "Something went wrong." });
  }
};
