#!/usr/bin/env node
// Check that every place that carries the release version agrees:
// the Cargo workspace, the app's package.json and package-lock.json,
// tauri.conf.json and the npm package. With `--tag vX.Y.Z` (or a full
// `refs/tags/vX.Y.Z`) the tag must match too.
//
//   node scripts/check-versions.mjs [--tag <tag>]
//
// Prints the version on success; lists the mismatches and exits 1 otherwise.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** The `version` of `[workspace.package]` in a Cargo.toml, or null. */
export function cargoWorkspaceVersion(toml) {
  let inSection = false;
  for (const raw of toml.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('[')) {
      inSection = line === '[workspace.package]';
      continue;
    }
    const m = inSection && line.match(/^version\s*=\s*"([^"]+)"/);
    if (m) return m[1];
  }
  return null;
}

/** `v1.2.3` or `refs/tags/v1.2.3` -> `1.2.3`; null if it is not a version tag. */
export function versionFromTag(tag) {
  const m = tag.replace(/^refs\/tags\//, '').match(/^v(.+)$/);
  return m && SEMVER.test(m[1]) ? m[1] : null;
}

/** Collect [label, version] pairs from the repository at `root`. */
export function collectVersions(root) {
  const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
  const json = (rel) => JSON.parse(read(rel));
  const lock = json('app/package-lock.json');
  return [
    ['Cargo.toml [workspace.package]', cargoWorkspaceVersion(read('Cargo.toml'))],
    ['app/package.json', json('app/package.json').version],
    ['app/package-lock.json', lock.version],
    ['app/package-lock.json packages[""]', lock.packages && lock.packages[''] && lock.packages[''].version],
    ['app/src-tauri/tauri.conf.json', json('app/src-tauri/tauri.conf.json').version],
    ['npm/package.json', json('npm/package.json').version],
  ];
}

/** Return a list of problems (empty when everything agrees). */
export function findMismatches(versions, tagVersion) {
  const problems = [];
  const expected = tagVersion || versions[0][1];
  if (!expected || !SEMVER.test(expected)) problems.push(`not a valid version: ${expected}`);
  for (const [label, v] of versions) {
    if (v !== expected) problems.push(`${label} is ${v ?? '(missing)'}, expected ${expected}`);
  }
  return problems;
}

function main(argv) {
  let tag = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--tag' && i + 1 < argv.length) tag = argv[++i];
    else {
      process.stderr.write(`usage: check-versions.mjs [--tag vX.Y.Z]\n`);
      return 1;
    }
  }
  let tagVersion = null;
  if (tag !== null) {
    tagVersion = versionFromTag(tag);
    if (!tagVersion) {
      process.stderr.write(`check-versions: ${tag} is not a vX.Y.Z tag\n`);
      return 1;
    }
  }
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const versions = collectVersions(root);
  const problems = findMismatches(versions, tagVersion);
  if (problems.length) {
    for (const p of problems) process.stderr.write(`check-versions: ${p}\n`);
    return 1;
  }
  process.stdout.write(`${tagVersion || versions[0][1]}\n`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
