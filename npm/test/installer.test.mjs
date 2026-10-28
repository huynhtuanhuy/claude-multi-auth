// Unit tests for the installer's pure parts. No network, no npm, no writes
// outside a temporary directory.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';

import {
  APP_BUNDLE,
  InstallerError,
  UsageError,
  appAssetName,
  appAssetUrl,
  appSearchDirs,
  checksumMatches,
  chooseAppsDir,
  download,
  expectedChecksum,
  findOnPath,
  isAllowedUrl,
  isAppRunningIn,
  npmCommand,
  parseArgs,
  parseChoice,
  uniqueTrashPath,
} from '../lib/installer.mjs';

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cma-installer-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** A fake HTTP response: readable body plus statusCode and headers. */
function response(statusCode, headers = {}, body = '') {
  const res = Readable.from(body ? [Buffer.from(body)] : []);
  res.statusCode = statusCode;
  res.headers = headers;
  return res;
}

test('parseArgs: selections, uninstall and yes', () => {
  assert.deepEqual(parseArgs([]), { mode: 'install', cli: false, app: false, yes: false });
  assert.deepEqual(parseArgs(['--cli']), { mode: 'install', cli: true, app: false, yes: false });
  assert.deepEqual(parseArgs(['--app', '-y']), { mode: 'install', cli: false, app: true, yes: true });
  assert.deepEqual(parseArgs(['--all']), { mode: 'install', cli: true, app: true, yes: false });
  assert.deepEqual(parseArgs(['--cli', '--app']), { mode: 'install', cli: true, app: true, yes: false });
  assert.deepEqual(parseArgs(['--uninstall', '--app', '--yes']), {
    mode: 'uninstall',
    cli: false,
    app: true,
    yes: true,
  });
  assert.equal(parseArgs(['--uninstall']).mode, 'uninstall');
});

test('parseArgs: help wins over version, both win over actions', () => {
  assert.equal(parseArgs(['--cli', '--version']).mode, 'version');
  assert.equal(parseArgs(['-v']).mode, 'version');
  assert.equal(parseArgs(['--version', '--help']).mode, 'help');
  assert.equal(parseArgs(['--uninstall', '-h']).mode, 'help');
});

test('parseArgs: rejects unknown options and positionals', () => {
  assert.throws(() => parseArgs(['--bogus']), (e) => e instanceof UsageError && /unknown option: --bogus/.test(e.message));
  assert.throws(() => parseArgs(['cli']), (e) => e instanceof UsageError && /unexpected argument: cli/.test(e.message));
  assert.throws(() => parseArgs(['--cli=yes']), UsageError);
});

test('parseChoice maps the menu', () => {
  assert.deepEqual(parseChoice('1'), { cli: true, app: false });
  assert.deepEqual(parseChoice(' 2 '), { cli: false, app: true });
  assert.deepEqual(parseChoice('3'), { cli: true, app: true });
  assert.deepEqual(parseChoice(''), { cli: true, app: true });
  assert.equal(parseChoice('4'), null);
  assert.equal(parseChoice('both'), null);
});

test('asset name and URL follow the release naming', () => {
  assert.equal(appAssetName('1.2.3'), 'Claude-Multi-Auth_1.2.3_universal.app.zip');
  assert.equal(
    appAssetUrl('1.2.3'),
    'https://github.com/huynhtuanhuy/claude-multi-auth/releases/download/v1.2.3/Claude-Multi-Auth_1.2.3_universal.app.zip',
  );
  assert.equal(appAssetUrl('0.1.0-rc.1', 'http://127.0.0.1:8123/assets'), 'http://127.0.0.1:8123/assets/Claude-Multi-Auth_0.1.0-rc.1_universal.app.zip');
});

test('isAllowedUrl: only https GitHub release hosts', () => {
  assert.ok(isAllowedUrl('https://github.com/huynhtuanhuy/claude-multi-auth/releases/download/v1/x.zip'));
  assert.ok(isAllowedUrl('https://objects.githubusercontent.com/github-production-release-asset/1?x=y'));
  assert.ok(isAllowedUrl('https://release-assets.githubusercontent.com/github-production-release-asset/1'));
  assert.ok(!isAllowedUrl('http://github.com/x.zip'), 'plain http');
  assert.ok(!isAllowedUrl('https://github.com:8443/x.zip'), 'non-default port');
  assert.ok(!isAllowedUrl('https://evil.example/x.zip'));
  assert.ok(!isAllowedUrl('https://github.com.evil.example/x.zip'));
  assert.ok(!isAllowedUrl('https://evilgithub.com/x.zip'));
  assert.ok(!isAllowedUrl('https://user:pw@github.com/x.zip'), 'credentials');
  assert.ok(!isAllowedUrl('file:///tmp/x.zip'));
  assert.ok(!isAllowedUrl('not a url'));
});

test('isAllowedUrl: a pinned origin allows only that origin', () => {
  const origin = 'http://127.0.0.1:8123';
  assert.ok(isAllowedUrl('http://127.0.0.1:8123/a/x.zip', origin));
  assert.ok(!isAllowedUrl('http://127.0.0.1:8124/a/x.zip', origin));
  assert.ok(!isAllowedUrl('https://github.com/x.zip', origin));
});

test('download follows allowed redirects and hashes the body', async (t) => {
  const dest = path.join(tempDir(t), 'app.zip');
  const body = 'zip bytes';
  const seen = [];
  const get = async (url) => {
    seen.push(url);
    if (url.startsWith('https://github.com/')) {
      return response(302, { location: 'https://objects.githubusercontent.com/asset?sig=1' });
    }
    return response(200, { 'content-length': String(body.length) }, body);
  };
  const digest = await download('https://github.com/o/r/releases/download/v1/x.zip', dest, { get });
  assert.equal(digest, sha256(body));
  assert.equal(fs.readFileSync(dest, 'utf8'), body);
  assert.deepEqual(seen, [
    'https://github.com/o/r/releases/download/v1/x.zip',
    'https://objects.githubusercontent.com/asset?sig=1',
  ]);
});

test('download refuses a redirect to a host outside the allowlist', async (t) => {
  const dest = path.join(tempDir(t), 'app.zip');
  const get = async () => response(302, { location: 'https://evil.example/x.zip' });
  await assert.rejects(
    download('https://github.com/x.zip', dest, { get }),
    (e) => e instanceof InstallerError && /evil\.example/.test(e.message),
  );
  assert.ok(!fs.existsSync(dest));
});

test('download refuses a downgrade to http', async (t) => {
  const dest = path.join(tempDir(t), 'app.zip');
  const get = async () => response(301, { location: 'http://github.com/x.zip' });
  await assert.rejects(download('https://github.com/x.zip', dest, { get }), InstallerError);
});

test('download stops after too many redirects', async (t) => {
  const dest = path.join(tempDir(t), 'app.zip');
  let n = 0;
  const get = async () => response(302, { location: `https://github.com/hop${++n}` });
  await assert.rejects(download('https://github.com/x.zip', dest, { get }), /too many redirects/);
});

test('download reports HTTP errors and oversize bodies', async (t) => {
  const dir = tempDir(t);
  await assert.rejects(
    download('https://github.com/x.zip', path.join(dir, 'a'), { get: async () => response(404) }),
    /HTTP 404/,
  );
  await assert.rejects(
    download('https://github.com/x.zip', path.join(dir, 'b'), {
      get: async () => response(200, { 'content-length': '100' }, 'x'.repeat(100)),
      maxBytes: 10,
    }),
    /too large/,
  );
  await assert.rejects(
    download('https://github.com/x.zip', path.join(dir, 'c'), {
      get: async () => response(200, {}, 'x'.repeat(100)),
      maxBytes: 10,
    }),
    /too large/,
  );
});

test('expectedChecksum reads checksums.json for the right version and asset', () => {
  const asset = appAssetName('1.0.0');
  const sum = 'a'.repeat(64);
  const text = JSON.stringify({ version: '1.0.0', files: { [asset]: sum.toUpperCase() } });
  assert.equal(expectedChecksum(text, '1.0.0', asset), sum);
  assert.throws(() => expectedChecksum(text, '1.0.1', asset), /not for version 1\.0\.1/);
  assert.throws(() => expectedChecksum(text, '1.0.0', 'other.zip'), /no SHA-256 for other\.zip/);
  assert.throws(() => expectedChecksum('{', '1.0.0', asset), /not valid JSON/);
  const short = JSON.stringify({ version: '1.0.0', files: { [asset]: 'abc' } });
  assert.throws(() => expectedChecksum(short, '1.0.0', asset), InstallerError);
});

test('checksumMatches compares hex digests', () => {
  const sum = sha256('x');
  assert.ok(checksumMatches(sum, sum.toUpperCase()));
  assert.ok(!checksumMatches(sum, sha256('y')));
  assert.ok(!checksumMatches(undefined, sum));
});

test('chooseAppsDir: override, upgrade in place, then /Applications, then ~/Applications', () => {
  const home = '/Users/test';
  const userDir = '/Users/test/Applications';
  const none = () => false;
  const all = () => true;
  assert.equal(chooseAppsDir({ override: '/tmp/apps', home, exists: all, writable: none }), '/tmp/apps');
  assert.equal(chooseAppsDir({ home, exists: none, writable: all }), '/Applications');
  assert.equal(chooseAppsDir({ home, exists: none, writable: (d) => d !== '/Applications' }), userDir);
  // Already installed in ~/Applications: upgrade it there.
  const inUser = (p) => p === path.join(userDir, APP_BUNDLE);
  assert.equal(chooseAppsDir({ home, exists: inUser, writable: all }), userDir);
  // Installed in /Applications but it is not writable now: fall back.
  const inSystem = (p) => p === path.join('/Applications', APP_BUNDLE);
  assert.equal(chooseAppsDir({ home, exists: inSystem, writable: (d) => d === userDir }), userDir);
});

test('appSearchDirs honours the override', () => {
  assert.deepEqual(appSearchDirs({ home: '/Users/t' }), ['/Applications', '/Users/t/Applications']);
  assert.deepEqual(appSearchDirs({ override: '/tmp/a', home: '/Users/t' }), ['/tmp/a']);
});

test('isAppRunningIn spots the app executable only', () => {
  const app = '/Applications/Claude Multi Auth.app/Contents/MacOS/claude-multi-auth';
  assert.ok(isAppRunningIn(`/sbin/launchd\n${app}\n/usr/bin/login`));
  assert.ok(isAppRunningIn(`${app} --flag`));
  assert.ok(!isAppRunningIn('/Applications/Claude Multi Auth.app/Contents/MacOS/cma list'));
  assert.ok(!isAppRunningIn('node /usr/local/bin/claude-multi-auth --app'));
  assert.ok(!isAppRunningIn('/x.app/Contents/MacOS/claude-multi-auth-helper'));
});

test('uniqueTrashPath picks a free Finder-style name', () => {
  const taken = new Set(['/T/Claude Multi Auth.app', '/T/Claude Multi Auth 2.app']);
  assert.equal(uniqueTrashPath('/T', 'Claude Multi Auth.app', (p) => taken.has(p)), '/T/Claude Multi Auth 3.app');
  assert.equal(uniqueTrashPath('/T', 'x', () => false), '/T/x');
});

test('npmCommand prefers the npm that launched the installer', () => {
  const exists = (p) => p === '/n/lib/node_modules/npm/bin/npm-cli.js';
  assert.deepEqual(npmCommand({}, '/n/bin/node', exists), { command: 'npm', prefixArgs: [] });
  assert.deepEqual(npmCommand({ npm_execpath: '/n/lib/node_modules/npm/bin/npm-cli.js' }, '/n/bin/node', exists), {
    command: '/n/bin/node',
    prefixArgs: ['/n/lib/node_modules/npm/bin/npm-cli.js'],
  });
  assert.deepEqual(npmCommand({ npm_execpath: '/n/lib/node_modules/npm/bin/npx-cli.js' }, '/n/bin/node', exists), {
    command: '/n/bin/node',
    prefixArgs: ['/n/lib/node_modules/npm/bin/npm-cli.js'],
  });
  // Another package manager: use npm from PATH.
  assert.deepEqual(npmCommand({ npm_execpath: '/x/pnpm.cjs' }, '/n/bin/node', exists), { command: 'npm', prefixArgs: [] });
});

test('findOnPath returns the first executable match', () => {
  const ok = new Set(['/b/cma', '/c/cma']);
  assert.equal(findOnPath('cma', '/a::/b:/c', (p) => ok.has(p)), '/b/cma');
  assert.equal(findOnPath('cma', '', () => true), null);
  assert.equal(findOnPath('cma', undefined, () => true), null);
});
