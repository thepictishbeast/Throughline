// Prove that pressing "Apply now" in the browser actually reroutes real
// traffic — and that "Undo" puts it back.
//
// Everything happens inside the namespaces scripts/netns-test.sh builds,
// against a tl-serve started with TL_NETNS pointing at them. The machine
// running the test is never touched.
//
//   sudo scripts/netns-test.sh            # leaves nothing behind; run first
//   sudo scripts/browser-apply-test.mjs   # via node, see README
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
const require = createRequire(process.env.TL_PLAYWRIGHT || `${process.cwd()}/package.json`);
const { chromium } = require('playwright');

const [url, token] = process.argv.slice(2);
// The policy is "everything through the tunnel", which needs no cgroup
// resolution — and nft resolving a cgroup path is exactly what a
// namespace's remounted /sys makes impossible. The cgroup selectors are
// proven by traffic in scripts/netns-test.sh instead.
let pass = 0, fail = 0;
const check = (ok, msg) => { console.log((ok ? 'PASS  ' : 'FAIL  ') + msg); ok ? pass++ : fail++; };

// Who answers tells us which path the packet took.
const ask = () => {
  try {
    return execFileSync('sh', ['-c',
      `exec nsenter --net=/var/run/netns/tl-app ` +
      `python3 -c 'import socket,sys
try:
    s=socket.create_connection(("10.9.9.9",9999),2); sys.stdout.write(s.recv(16).decode())
except Exception: sys.stdout.write("UNREACHABLE")'`],
      { encoding: 'utf8', timeout: 9000 }).trim();
  } catch { return 'ERROR'; }
};

const b = await chromium.launch({ args: ['--no-sandbox'] });
const p = await b.newPage({ viewport: { width: 1500, height: 1000 } });
const errs = [];
p.on('pageerror', e => errs.push(e.message));
await p.goto(url, { waitUntil: 'networkidle' });
await p.click('#tab-route');
// Not waiting for a chip: `ip netns exec` remounts /sys, so the server
// inside the namespace has no cgroup list to offer. The policy under test
// is the default path, which needs none.
await p.waitForSelector('#doapply');
await p.waitForFunction(() => R.host !== null, null, { timeout: 15000 });

check(ask() === 'ISP', 'before: traffic takes the ordinary route');

// Refuse without the token, from the page itself.
await p.fill('#token', 'not-the-token');
await p.evaluate(() => { R.dflt = 'vpn'; R.iface = 'tl-w0'; return refreshPlan(); });
// Wait for the CONDITION, not a guessed number of milliseconds: the plan
// fetch has to land before the button is offered.
await p.waitForFunction(() => !document.getElementById('doapply').disabled,
                        null, { timeout: 15000 });
await p.click('#doapply');
await p.waitForFunction(() => document.getElementById('actionsaid').textContent
                              && document.getElementById('actionsaid').textContent !== 'working…',
                        null, { timeout: 20000 });
const refused = await p.textContent('#actionsaid');
check(/token/i.test(refused), `a wrong token is refused in the page ("${refused.slice(0, 48)}…")`);
check(ask() === 'ISP', 'and nothing was applied');

// Now with the real one.
await p.fill('#token', token);
await p.evaluate(() => { R.dflt = 'vpn'; R.iface = 'tl-w0'; return refreshPlan(); });
await p.waitForFunction(() => !document.getElementById('doapply').disabled,
                        null, { timeout: 15000 });
await p.click('#doapply');
await p.waitForFunction(() => /undoes itself|error|could not/i.test(
                          document.getElementById('actionsaid').textContent),
                        null, { timeout: 20000 });
const said = await p.textContent('#actionsaid');
check(/undoes itself/.test(said), `the page reports the countdown ("${said.slice(0, 56)}…")`);
check(ask() === 'VPN', 'pressing Apply in the browser reroutes real traffic');

const status = await p.textContent('#applied');
check(/unless confirmed/.test(status), `the page reads back what is applied ("${status.slice(0, 48)}")`);

await p.waitForFunction(() => !document.getElementById('dorevert').disabled,
                        null, { timeout: 15000 });
await p.click('#dorevert');
await p.waitForFunction(() => /reverted|error|nothing/i.test(
                          document.getElementById('actionsaid').textContent),
                        null, { timeout: 20000 });
check(ask() === 'ISP', 'pressing Undo puts it back');
check(errs.length === 0, `no page errors${errs.length ? ': ' + errs.join(' | ') : ''}`);

await p.screenshot({ path: '/tank/scratch/browser-apply.png' });
await b.close();
console.log(`\n=== ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
