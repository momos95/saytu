const cp = require('child_process');
const crypto = require('crypto');
const https = require('https');

function evals(userCode, name) {
  // ruleid: saytu.js.eval-injection
  eval(userCode);
  // ruleid: saytu.js.eval-injection
  eval("var x = " + name);
  // ok: saytu.js.eval-injection
  eval("1 + 1");
  // ok: saytu.js.eval-injection
  setTimeout(() => run(), 100);
  // ok: saytu.js.eval-injection
  setTimeout(resolve);
  // ruleid: saytu.js.eval-injection
  setTimeout("run('" + name + "')", 10);
  // ruleid: saytu.js.eval-injection
  new Function("a", userCode);
}

function commands(file) {
  // ruleid: saytu.js.command-injection
  cp.exec("convert " + file + " out.png");
  // ruleid: saytu.js.command-injection
  cp.execSync(`ls ${file}`);
  // ok: saytu.js.command-injection
  cp.execFile("/usr/bin/convert", [file, "out.png"]);
}

function tls() {
  // ruleid: saytu.js.tls-verification-disabled
  https.request({ host: "example.org", rejectUnauthorized: false });
  // ruleid: saytu.js.tls-verification-disabled
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  // ok: saytu.js.tls-verification-disabled
  https.request({ host: "example.org", rejectUnauthorized: true });
}

function dom(el, comment) {
  // ruleid: saytu.js.dom-xss-innerhtml
  el.innerHTML = comment;
  // ok: saytu.js.dom-xss-innerhtml
  el.innerHTML = "<b>static</b>";
  // ok: saytu.js.dom-xss-innerhtml
  el.innerHTML = DOMPurify.sanitize(comment);
  // ok: saytu.js.dom-xss-innerhtml
  el.textContent = comment;
}

function hashes(data) {
  // ruleid: saytu.js.weak-hash
  crypto.createHash("md5").update(data);
  // ruleid: saytu.js.weak-hash
  crypto.createHash("sha1").update(data);
  // ok: saytu.js.weak-hash
  crypto.createHash("sha256").update(data);
}

async function sql(db, id, name) {
  // ruleid: saytu.js.sql-injection
  await db.query("SELECT * FROM users WHERE id = " + id);
  // ruleid: saytu.js.sql-injection
  await db.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ok: saytu.js.sql-injection
  await db.query("SELECT * FROM users WHERE id = $1", [id]);
}
