// The claude-multi-auth installer: installs the `cma` command line tool
// (through npm), the Claude Multi Auth menubar app (from the GitHub release
// of the same version), or both, and uninstalls them again.
//
// Node built-ins only, no dependencies. The functions near the top are pure
// or take their side effects as arguments, so the tests can run them without
// the network, without npm and without writing to /Applications. `main` at the
// bottom wires them to the real system.
//
// Environment variables for testing only (never needed by users):
//   CMA_INSTALLER_APPS_DIR   install into / uninstall from this directory
//                            instead of /Applications and ~/Applications.
//   CMA_INSTALLER_BASE_URL   download the app from this base URL instead of
//                            the GitHub release. Only that exact origin is
//                            then allowed, plain http included.
//   CMA_INSTALLER_TRASH_DIR  move removed apps into this directory instead
//                            of the user's Trash.
// The SHA-256 check against checksums.json is never skipped.

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { fileURLToPath } from 'node:url';

export const PACKAGE_NAME = 'claude-multi-auth';
export const REPO = 'huynhtuanhuy/claude-multi-auth';
const UNINSTALL_DOCS = `https://github.com/${REPO}/blob/main/docs/install.md#uninstall`;
export const APP_BUNDLE = 'Claude Multi Auth.app';
export const APP_BUNDLE_ID = 'dev.claude-multi-auth.menubar';
export const SYSTEM_APPS_DIR = '/Applications';

/** Hosts a GitHub release download may be served from (after redirects). */
export const RELEASE_HOSTS = Object.freeze([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
]);

const MAX_REDIRECTS = 5;
// The zipped app is around 20 MB; anything far larger is not our asset.
const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;

/** An error whose message is meant for the user as is (no stack trace). */
export class InstallerError extends Error {}

/** A bad command line; main prints the usage after the message. */
export class UsageError extends InstallerError {}

export const HELP = `Usage: claude-multi-auth [options]

Installs claude-multi-auth on this Mac: the \`cma\` command line tool, the
Claude Multi Auth menubar app, or both. Without options on a terminal it asks
what to install.

Options:
  --cli          Install the command line tool (npm install -g).
  --app          Install the menubar app into /Applications
                 (or ~/Applications when /Applications is not writable).
  --all          Install both.
  --uninstall    Uninstall instead; combine with --cli, --app or --all.
  -y, --yes      Do not ask for confirmation.
  -v, --version  Print the installer version.
  -h, --help     Print this help.

The app is always the same version as this installer. Your accounts and
backups in ~/.claude-multi-auth are never touched.
`;

// ---------------------------------------------------------------------------
// Command line

/**
 * Parse the installer's arguments (without `node` and the script path).
 * Returns { mode, cli, app, yes } where mode is 'help', 'version', 'install'
 * or 'uninstall', and cli/app say which parts were selected by flags.
 */
export function parseArgs(argv) {
  const opts = { mode: 'install', cli: false, app: false, yes: false };
  let help = false;
  let version = false;
  for (const arg of argv) {
    switch (arg) {
      case '--cli':
        opts.cli = true;
        break;
      case '--app':
        opts.app = true;
        break;
      case '--all':
        opts.cli = true;
        opts.app = true;
        break;
      case '--uninstall':
        opts.mode = 'uninstall';
        break;
      case '-y':
      case '--yes':
        opts.yes = true;
        break;
      case '-v':
      case '--version':
        version = true;
        break;
      case '-h':
      case '--help':
        help = true;
        break;
      default:
        throw new UsageError(
          arg.startsWith('-') ? `unknown option: ${arg}` : `unexpected argument: ${arg}`,
        );
    }
  }
  if (help) opts.mode = 'help';
  else if (version) opts.mode = 'version';
  return opts;
}

/** Map an interactive menu answer to { cli, app }, or null if invalid. */
export function parseChoice(answer) {
  switch (answer.trim()) {
    case '1':
      return { cli: true, app: false };
    case '2':
      return { cli: false, app: true };
    case '':
    case '3':
      return { cli: true, app: true };
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Release download

/** File name of the zipped app in the GitHub release of `version`. */
export function appAssetName(version) {
  return `Claude-Multi-Auth_${version}_universal.app.zip`;
}

/** Download URL of the zipped app; `baseUrl` is the testing override. */
export function appAssetUrl(version, baseUrl) {
  const base = baseUrl || `https://github.com/${REPO}/releases/download/v${version}/`;
  return new URL(appAssetName(version), base.endsWith('/') ? base : `${base}/`).href;
}

/**
 * Whether the installer may fetch `url`. Normally only https on the default
 * port to the GitHub release hosts, without credentials in the URL. With
 * `pinnedOrigin` (the testing override) only that exact origin is allowed.
 */
export function isAllowedUrl(url, pinnedOrigin) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.username || u.password) return false;
  if (pinnedOrigin) return u.origin === pinnedOrigin;
  return u.protocol === 'https:' && u.port === '' && RELEASE_HOSTS.includes(u.hostname);
}

/** The default HTTP(S) GET used by download(); resolves with the response. */
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const client = new URL(url).protocol === 'http:' ? http : https;
    const req = client.get(url, { headers: { 'user-agent': `${PACKAGE_NAME}-installer` } }, resolve);
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new InstallerError(`download timed out: ${url}`));
    });
    req.on('error', reject);
  });
}

/**
 * Download `url` to `dest`, following redirects that stay on allowed hosts,
 * and resolve with the SHA-256 (hex) of what was written. `get(url)` must
 * resolve with a readable response that has `statusCode` and `headers`.
 */
export async function download(url, dest, { get = httpGet, pinnedOrigin, maxBytes = MAX_DOWNLOAD_BYTES } = {}) {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!isAllowedUrl(current, pinnedOrigin)) {
      throw new InstallerError(`refusing to download from ${current}: not a GitHub release host`);
    }
    const res = await get(current);
    const status = res.statusCode;
    if ([301, 302, 303, 307, 308].includes(status)) {
      res.resume();
      const location = res.headers.location;
      if (!location) throw new InstallerError(`redirect without a location from ${current}`);
      current = new URL(location, current).href;
      continue;
    }
    if (status !== 200) {
      res.resume();
      throw new InstallerError(`download failed: HTTP ${status} for ${current}`);
    }
    const declared = Number(res.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      res.destroy();
      throw new InstallerError(`download too large (${declared} bytes): ${current}`);
    }
    return writeAndHash(res, dest, maxBytes);
  }
  throw new InstallerError(`too many redirects downloading ${url}`);
}

/** Stream `res` into `dest` while hashing it; resolves with the hex digest. */
function writeAndHash(res, dest, maxBytes) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const out = fs.createWriteStream(dest, { mode: 0o600 });
    let size = 0;
    let failed = false;
    const fail = (err) => {
      if (failed) return;
      failed = true;
      res.destroy();
      out.destroy();
      reject(err);
    };
    res.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        fail(new InstallerError(`download too large (over ${maxBytes} bytes)`));
        return;
      }
      hash.update(chunk);
    });
    res.on('error', fail);
    out.on('error', fail);
    out.on('finish', () => {
      if (!failed) resolve(hash.digest('hex'));
    });
    res.pipe(out);
  });
}

/**
 * Read the expected SHA-256 of `asset` from the checksums.json that the
 * release workflow embeds in the npm package:
 *   { "version": "X.Y.Z", "files": { "<asset>": "<64 hex digits>" } }
 */
export function expectedChecksum(checksumsText, version, asset) {
  let data;
  try {
    data = JSON.parse(checksumsText);
  } catch {
    throw new InstallerError('checksums.json in this package is not valid JSON');
  }
  if (!data || typeof data !== 'object' || data.version !== version) {
    throw new InstallerError(`checksums.json in this package is not for version ${version}`);
  }
  const sum = data.files && data.files[asset];
  if (typeof sum !== 'string' || !/^[0-9a-f]{64}$/i.test(sum)) {
    throw new InstallerError(`checksums.json in this package has no SHA-256 for ${asset}`);
  }
  return sum.toLowerCase();
}

/** Whether a computed hex digest equals the expected one. */
export function checksumMatches(actual, expected) {
  return typeof actual === 'string' && typeof expected === 'string' && actual.toLowerCase() === expected.toLowerCase();
}

// ---------------------------------------------------------------------------
// Where the app goes

/**
 * Pick the directory to install the app into. An override (testing) wins.
 * Otherwise an existing install is upgraded in place when its directory is
 * writable; else /Applications when writable; else ~/Applications.
 * `exists(path)` and `writable(dir)` are injected.
 */
export function chooseAppsDir({ override, home, exists, writable }) {
  if (override) return override;
  const userDir = path.join(home, 'Applications');
  for (const dir of [SYSTEM_APPS_DIR, userDir]) {
    if (exists(path.join(dir, APP_BUNDLE)) && writable(dir)) return dir;
  }
  return writable(SYSTEM_APPS_DIR) ? SYSTEM_APPS_DIR : userDir;
}

/** Directories an installed app may be in (for uninstall). */
export function appSearchDirs({ override, home }) {
  return override ? [override] : [SYSTEM_APPS_DIR, path.join(home, 'Applications')];
}

/** Whether `ps -axo command=` output shows the menubar app running. */
export function isAppRunningIn(psOutput) {
  return /\.app\/Contents\/MacOS\/claude-multi-auth(\s|$)/m.test(psOutput);
}

/**
 * A name for `base` inside `dir` that does not exist yet, Finder style:
 * "Claude Multi Auth.app", then "Claude Multi Auth 2.app", and so on.
 */
export function uniqueTrashPath(dir, base, exists) {
  const ext = path.extname(base);
  const stem = base.slice(0, base.length - ext.length);
  for (let n = 1; n < 1000; n++) {
    const candidate = path.join(dir, n === 1 ? base : `${stem} ${n}${ext}`);
    if (!exists(candidate)) return candidate;
  }
  throw new InstallerError(`could not find a free name for ${base} in ${dir}`);
}

/**
 * How to run npm: the npm that started us when we run under npm/npx
 * (npm_execpath), so a global install lands in the same prefix; otherwise
 * `npm` from PATH. Returns { command, prefixArgs }.
 */
export function npmCommand(env, nodePath, exists) {
  const execPath = env.npm_execpath;
  if (execPath) {
    const base = path.basename(execPath);
    if (base === 'npm-cli.js') return { command: nodePath, prefixArgs: [execPath] };
    if (base === 'npx-cli.js') {
      const sibling = path.join(path.dirname(execPath), 'npm-cli.js');
      if (exists(sibling)) return { command: nodePath, prefixArgs: [sibling] };
    }
  }
  return { command: 'npm', prefixArgs: [] };
}

/** The first `name` executable on `pathEnv`, or null. */
export function findOnPath(name, pathEnv, isExecutable) {
  for (const dir of (pathEnv || '').split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Side effects (wired to the real system in main)

/** Run a command without a shell. Resolves with { code, stdout, stderr }. */
export function run(command, args, { inherit = false, env = process.env } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env,
      shell: false,
      stdio: inherit ? 'inherit' : ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    if (!inherit) {
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
    }
    child.on('error', (err) => reject(new InstallerError(`could not run ${command}: ${err.message}`)));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function existsSync(p) {
  try {
    fs.lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

function writableSync(dir) {
  try {
    fs.accessSync(dir, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function executableSync(p) {
  try {
    fs.accessSync(p, fs.constants.X_OK);
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function realpathOrSelf(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

/** Read a key from an app bundle's Info.plist, or null. */
async function plistValue(appPath, key) {
  const plist = path.join(appPath, 'Contents', 'Info.plist');
  const r = await run('/usr/bin/plutil', ['-extract', key, 'raw', '-o', '-', plist]);
  return r.code === 0 ? r.stdout.trim() : null;
}

/** The context main builds; tests never construct it. */
function systemContext(env, version, packageDir) {
  const home = os.homedir();
  const baseUrl = env.CMA_INSTALLER_BASE_URL || '';
  return {
    env,
    version,
    home,
    packageDir,
    appsOverride: env.CMA_INSTALLER_APPS_DIR || '',
    trashOverride: env.CMA_INSTALLER_TRASH_DIR || '',
    baseUrl,
    pinnedOrigin: baseUrl ? new URL(baseUrl).origin : '',
    interactive: Boolean(process.stdin.isTTY && process.stdout.isTTY),
    yes: false,
    log: (msg) => process.stdout.write(`${msg}\n`),
    npm: npmCommand(env, process.execPath, existsSync),
  };
}

async function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await rl.question(question);
  } finally {
    rl.close();
  }
}

/** Ask a yes/no question; --yes answers yes, a non-terminal cannot answer. */
async function confirm(ctx, question) {
  if (ctx.yes) return true;
  if (!ctx.interactive) {
    throw new InstallerError(`${question} Re-run with --yes to confirm without a terminal.`);
  }
  const answer = (await ask(`${question} [y/N] `)).trim().toLowerCase();
  return answer === 'y' || answer === 'yes';
}

async function appRunning() {
  const r = await run('/bin/ps', ['-axo', 'command=']);
  if (r.code !== 0) throw new InstallerError('could not list running processes (ps failed)');
  return isAppRunningIn(r.stdout);
}

/** Wait until the app is not running: ask on a terminal, fail otherwise. */
async function ensureAppNotRunning(ctx) {
  while (await appRunning()) {
    const msg = 'Claude Multi Auth is running. Quit it from its menubar menu (Quit) first.';
    if (!ctx.interactive) throw new InstallerError(msg);
    await ask(`${msg}\nPress Enter when it has quit (Ctrl-C to cancel). `);
  }
}

/** Move `p` to the Trash (or the testing trash directory). */
async function moveToTrash(ctx, p) {
  if (!ctx.trashOverride && existsSync('/usr/bin/trash')) {
    const r = await run('/usr/bin/trash', ['-s', p]);
    if (r.code === 0 && !existsSync(p)) return;
    // Fall through to a plain move into ~/.Trash.
  }
  const trashDir = ctx.trashOverride || path.join(ctx.home, '.Trash');
  await fsp.mkdir(trashDir, { recursive: true });
  const target = uniqueTrashPath(trashDir, path.basename(p), existsSync);
  try {
    await fsp.rename(p, target);
  } catch (err) {
    throw new InstallerError(`could not move ${p} to the Trash (${err.code || err.message}); delete it yourself`);
  }
}

// ---------------------------------------------------------------------------
// The four operations

async function npmGlobalPrefix(ctx) {
  const r = await run(ctx.npm.command, [...ctx.npm.prefixArgs, 'prefix', '-g'], { env: ctx.env });
  if (r.code !== 0) throw new InstallerError(`could not find npm's global prefix: ${r.stderr.trim()}`);
  return r.stdout.trim();
}

/** Version of claude-multi-auth installed in npm's global prefix, or null. */
function globalVersion(prefix) {
  const pkg = path.join(prefix, 'lib', 'node_modules', PACKAGE_NAME, 'package.json');
  try {
    return JSON.parse(fs.readFileSync(pkg, 'utf8')).version || null;
  } catch {
    return null;
  }
}

function reportCmaOnPath(ctx, cmaPath) {
  ctx.log(`cma is at ${cmaPath}`);
  const found = findOnPath('cma', ctx.env.PATH, executableSync);
  if (!found) {
    ctx.log(`Note: ${path.dirname(cmaPath)} is not on your PATH; add it to run \`cma\` by name.`);
  } else if (realpathOrSelf(found) !== realpathOrSelf(cmaPath)) {
    ctx.log(`Note: \`cma\` on your PATH is ${found}, which comes first. Remove it or reorder PATH`);
    ctx.log('      to use the npm one (the app\'s Install CLI link lives at ~/.local/bin/cma).');
  }
}

async function installCli(ctx) {
  const prefix = await npmGlobalPrefix(ctx);
  const cmaPath = path.join(prefix, 'bin', 'cma');
  if (globalVersion(prefix) === ctx.version && existsSync(cmaPath)) {
    ctx.log(`Command line tool ${ctx.version} is already installed.`);
  } else {
    const spec = `${PACKAGE_NAME}@${ctx.version}`;
    ctx.log(`Installing the command line tool: npm install -g ${spec}`);
    const r = await run(ctx.npm.command, [...ctx.npm.prefixArgs, 'install', '-g', spec], {
      inherit: true,
      env: ctx.env,
    });
    if (r.code !== 0) {
      throw new InstallerError(
        `npm install -g ${spec} failed (exit ${r.code}). If it was a permission error (EACCES), ` +
          'point npm at a prefix you own instead of using sudo: ' +
          'https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally',
      );
    }
    ctx.log(`Installed the command line tool ${ctx.version}.`);
  }
  reportCmaOnPath(ctx, cmaPath);
}

async function installApp(ctx) {
  const asset = appAssetName(ctx.version);
  const checksumsText = await fsp.readFile(path.join(ctx.packageDir, 'checksums.json'), 'utf8').catch(() => {
    throw new InstallerError('this package has no checksums.json, so the app cannot be verified');
  });
  const expected = expectedChecksum(checksumsText, ctx.version, asset);
  const appsDir = chooseAppsDir({
    override: ctx.appsOverride,
    home: ctx.home,
    exists: existsSync,
    writable: writableSync,
  });
  const dest = path.join(appsDir, APP_BUNDLE);
  if (existsSync(dest)) {
    const id = await plistValue(dest, 'CFBundleIdentifier');
    if (id !== APP_BUNDLE_ID) {
      throw new InstallerError(`${dest} exists but is not Claude Multi Auth (${id || 'no bundle id'}); not replacing it`);
    }
  }
  await ensureAppNotRunning(ctx);

  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'claude-multi-auth-'));
  let staging = '';
  try {
    const url = appAssetUrl(ctx.version, ctx.baseUrl);
    const zip = path.join(tmp, asset);
    ctx.log(`Downloading ${url}`);
    const actual = await download(url, zip, { pinnedOrigin: ctx.pinnedOrigin });
    if (!checksumMatches(actual, expected)) {
      throw new InstallerError(
        `SHA-256 mismatch for ${asset}: expected ${expected}, got ${actual}. Nothing was installed.`,
      );
    }
    ctx.log('Checksum verified.');

    await fsp.mkdir(appsDir, { recursive: true });
    // Extract next to the destination so the final step is a same-directory
    // rename, never a cross-volume copy.
    staging = await fsp.mkdtemp(path.join(appsDir, '.claude-multi-auth-install-'));
    const x = await run('/usr/bin/ditto', ['-x', '-k', zip, staging]);
    if (x.code !== 0) throw new InstallerError(`could not extract ${asset}: ${x.stderr.trim()}`);
    const fresh = path.join(staging, APP_BUNDLE);
    const [id, shortVersion] = [
      await plistValue(fresh, 'CFBundleIdentifier'),
      await plistValue(fresh, 'CFBundleShortVersionString'),
    ];
    if (id !== APP_BUNDLE_ID || shortVersion !== ctx.version) {
      throw new InstallerError(`${asset} does not contain Claude Multi Auth ${ctx.version}`);
    }

    // The user may have started the app while we downloaded.
    await ensureAppNotRunning(ctx);
    const old = path.join(staging, 'previous', APP_BUNDLE);
    const replacing = existsSync(dest);
    if (replacing) {
      await fsp.mkdir(path.dirname(old));
      await fsp.rename(dest, old);
    }
    try {
      await fsp.rename(fresh, dest);
    } catch (err) {
      if (replacing) await fsp.rename(old, dest).catch(() => {});
      throw new InstallerError(`could not move the app into ${appsDir}: ${err.code || err.message}`);
    }
    if (replacing) {
      await moveToTrash(ctx, old);
      ctx.log('Moved the previous version to the Trash.');
    }
    ctx.log(`Installed Claude Multi Auth ${ctx.version} to ${dest}`);
    ctx.log('Open it from Applications or Spotlight; it lives in the menubar.');
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
    if (staging) await fsp.rm(staging, { recursive: true, force: true });
  }
}

async function uninstallCli(ctx) {
  const prefix = await npmGlobalPrefix(ctx);
  if (!globalVersion(prefix)) {
    ctx.log(`The command line tool is not installed with npm (no ${PACKAGE_NAME} in ${prefix}).`);
  } else {
    const r = await run(ctx.npm.command, [...ctx.npm.prefixArgs, 'uninstall', '-g', PACKAGE_NAME], {
      inherit: true,
      env: ctx.env,
    });
    if (r.code !== 0) throw new InstallerError(`npm uninstall -g ${PACKAGE_NAME} failed (exit ${r.code})`);
    ctx.log('Uninstalled the command line tool.');
  }
  const link = path.join(ctx.home, '.local', 'bin', 'cma');
  if (existsSync(link)) {
    ctx.log(`Note: ${link} (the app's Install CLI link) is still there; remove it with: rm ${link}`);
  }
}

async function uninstallApp(ctx) {
  const found = [];
  for (const dir of appSearchDirs({ override: ctx.appsOverride, home: ctx.home })) {
    const p = path.join(dir, APP_BUNDLE);
    if (existsSync(p) && (await plistValue(p, 'CFBundleIdentifier')) === APP_BUNDLE_ID) found.push(p);
  }
  if (found.length === 0) {
    ctx.log('The menubar app is not installed.');
    return;
  }
  await ensureAppNotRunning(ctx);
  for (const p of found) {
    await moveToTrash(ctx, p);
    ctx.log(`Moved ${p} to the Trash.`);
  }
  ctx.log(`If "Launch at login" was on, also remove its LaunchAgent: see ${UNINSTALL_DOCS}`);
}

// ---------------------------------------------------------------------------
// Entry point

async function chooseInteractively(ctx, verb) {
  ctx.log(`Claude Multi Auth installer ${ctx.version}\n`);
  ctx.log(`What do you want to ${verb}?`);
  ctx.log('  1) Command line tool (cma)');
  ctx.log('  2) Menubar app (Claude Multi Auth.app)');
  ctx.log('  3) Both');
  for (;;) {
    const choice = parseChoice(await ask('Choice [3]: '));
    if (choice) return choice;
    ctx.log('Please answer 1, 2 or 3.');
  }
}

/**
 * Run the installer. `packageDir` is the npm package root (where
 * package.json and checksums.json are). Resolves with the exit code.
 */
export async function main(argv, { env = process.env, packageDir } = {}) {
  const dir = packageDir || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`claude-multi-auth: ${err.message}\n\n${HELP}`);
    return 1;
  }
  const version = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
  if (opts.mode === 'help') {
    process.stdout.write(HELP);
    return 0;
  }
  if (opts.mode === 'version') {
    process.stdout.write(`${version}\n`);
    return 0;
  }

  const ctx = systemContext(env, version, dir);
  ctx.yes = opts.yes;
  try {
    if (process.platform !== 'darwin') throw new InstallerError('claude-multi-auth runs on macOS only');
    const verb = opts.mode === 'uninstall' ? 'uninstall' : 'install';
    let { cli, app } = opts;
    if (!cli && !app) {
      if (!ctx.interactive) {
        process.stderr.write(`claude-multi-auth: choose --cli, --app or --all (no terminal to ask on)\n\n${HELP}`);
        return 1;
      }
      ({ cli, app } = await chooseInteractively(ctx, verb));
    }
    if (opts.mode === 'uninstall') {
      const what = [cli && 'the command line tool', app && 'the menubar app'].filter(Boolean).join(' and ');
      if (!(await confirm(ctx, `Uninstall ${what}?`))) {
        ctx.log('Nothing changed.');
        return 1;
      }
      if (app) await uninstallApp(ctx);
      if (cli) await uninstallCli(ctx);
      ctx.log(`Your accounts and backups in ~/.claude-multi-auth were kept. To remove them, see ${UNINSTALL_DOCS}`);
    } else {
      if (app) await installApp(ctx);
      if (cli) await installCli(ctx);
      if (cli || app) ctx.log('\nNext: run `cma import-current --alias <name>` or open the app to add accounts.');
    }
    return 0;
  } catch (err) {
    const msg = err instanceof InstallerError ? err.message : err && err.stack ? err.stack : String(err);
    process.stderr.write(`claude-multi-auth: ${msg}\n`);
    return 1;
  }
}
