// Drives the real UI in a real browser and asserts what a person would
// see. Every check here exists because the thing it checks was once
// wrong: tables ran past the panel edge, "1 flows", and — the one that
// mattered — clicking one process lit 16 destinations when it had
// touched 3, two of them Tor guard relays only `tor` talks to.
//
// Reading the DOM the user sees, not the page's internals, is the point:
// a check against `graph` would have passed while the screen lied.
//
//   tl-serve 7645 &
//   node scripts/verify-gui.mjs http://127.0.0.1:7645/ /tmp/shot
//
// Playwright is not vendored here (this repo has no dependencies). Run
// from a directory whose node_modules has it, or set TL_PLAYWRIGHT to
// any package.json whose tree does.

import { createRequire } from 'node:module';
// Resolve playwright from wherever the caller has it. Nothing is
// vendored here, so this is the one thing the script cannot detect.
const require = createRequire(process.env.TL_PLAYWRIGHT || `${process.cwd()}/package.json`);
const { chromium } = require('playwright');
const url = process.argv[2] || 'http://127.0.0.1:7644/';
const out = process.argv[3] || '/tmp/throughline';
const b = await chromium.launch({ args: ['--no-sandbox'] });
const errs = [];
let fails = 0;
const check = (ok, msg) => { console.log((ok ? 'PASS  ' : 'FAIL  ') + msg); if (!ok) fails++; };

for (const [w, h, tag] of [[1600,1000,'wide'], [900,1100,'narrow'], [420,900,'phone']]) {
  const p = await b.newPage({ viewport: { width: w, height: h } });
  p.on('console', m => { if (m.type() === 'error') errs.push(`${tag}: ${m.text()}`); });
  p.on('pageerror', e => errs.push(`${tag}: ${e.message}`));
  await p.goto(url, { waitUntil: 'networkidle' });
  await p.waitForFunction(() => document.getElementById('rows')?.children.length > 0,
                          null, { timeout: 15000 });
  await p.screenshot({ path: `${out}-${tag}.png` });
  const v = await p.evaluate(() => ({
    hScroll: document.documentElement.scrollWidth > window.innerWidth + 1,
    clipped: [...document.querySelectorAll('td')]
               .filter(c => c.getBoundingClientRect().right > window.innerWidth + 0.5).length,
    junk: /undefined|NaN|\\b1 (flows|connections|local hops)\\b/.test(document.body.innerText),
    emptyLanes: ['l-device','l-software','l-proxy','l-nic','l-dest']
                  .filter(id => !document.getElementById(id).children.length),
    // A node's NAME may ellipse (the title carries it in full), but its
    // meta must fit: ":53 · 96 connections · stops here" truncating to
    // "…· s…" hid the one fact that line exists to report.
    clippedMeta: [...document.querySelectorAll('.node .m')]
                   .filter(m => m.scrollWidth > m.clientWidth + 1)
                   .map(m => m.textContent),
  }));
  check(!v.hScroll, `${tag}: page body does not scroll sideways`);
  check(v.clipped === 0, `${tag}: no table cell past the panel edge (${v.clipped})`);
  check(!v.junk, `${tag}: no undefined/NaN/plural bug on screen`);
  check(!v.emptyLanes.length, `${tag}: every lane populated (${v.emptyLanes})`);
  check(!v.clippedMeta.length, `${tag}: no node detail truncated (${v.clippedMeta.slice(0,2)})`);

  if (tag === 'wide') {
    const api = await (await fetch(url + 'api/snapshot')).json();
    // Clicking a DESTINATION must light only the software that touched it.
    const dst = await p.$$eval('#l-dest .node', ns => ns[0].dataset.id.slice(4));
    const litSw = await p.evaluate((d) => {
      document.querySelector(`[data-id="dst:${CSS.escape(d)}"]`).click();
      return [...document.querySelectorAll('#l-software .node')]
        .filter(n => !n.classList.contains('dim')).map(n => n.dataset.id.slice(3)).sort();
    }, dst);
    const direct = new Set(api.flows.filter(f => f.dir === 'outbound' && f.remote === dst)
                                    .map(f => f.actor));
    check(litSw.every(a => direct.has(a)),
      `clicking ${dst.slice(0,22)} lights only software that reached it ` +
      `(${litSw.length} lit, ${direct.size} truly reached it)`);
    await p.evaluate((d) => document.querySelector(`[data-id="dst:${CSS.escape(d)}"]`).click(), dst);

    const sel = await p.evaluate(() => {
      document.querySelector('#l-software .node').click();
      return { sel: document.querySelectorAll('.node.sel').length,
               dim: document.querySelectorAll('.node.dim').length,
               lit: [...document.querySelectorAll('#wires path')]
                      .filter(x => +x.getAttribute('opacity') > 0.5).length };
    });
    check(sel.sel === 1 && sel.dim > 0 && sel.lit > 0,
      `selecting one node dims the rest (sel=${sel.sel} dim=${sel.dim} lit=${sel.lit})`);
    await p.waitForTimeout(300);   // let the .12s dim transition settle
    await p.screenshot({ path: `${out}-selected.png` });
    const hdr = await p.evaluate(() => [...document.querySelectorAll('th')]
      .filter(t => t.scrollWidth > t.clientWidth + 1).map(t => t.textContent));
    check(hdr.length === 0, `no truncated table header (${hdr})`);
  }
  await p.close();
}
check(errs.length === 0, `no console errors${errs.length ? ': ' + errs.join(' | ') : ''}`);
await b.close();
console.log(fails ? `\n${fails} CHECK(S) FAILED` : '\nall checks passed');
process.exit(fails ? 1 : 0);
