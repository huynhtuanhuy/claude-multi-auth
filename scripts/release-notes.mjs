#!/usr/bin/env node
// Print the CHANGELOG.md section of one version, for the GitHub release
// notes. Fails when the section is missing or empty, and when its heading
// still says "unreleased" (unless --allow-unreleased, used by dry runs).
//
//   node scripts/release-notes.mjs <version> [--allow-unreleased]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/**
 * Find the `## [version]` section of a Keep a Changelog file.
 * Returns { heading, body } or null when there is no such section.
 */
export function changelogSection(text, version) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.startsWith(`## [${version}]`));
  if (start === -1) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    // The next version section, or the link references at the bottom.
    if (lines[i].startsWith('## ') || /^\[[^\]]+\]:\s/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return { heading: lines[start], body: lines.slice(start + 1, end).join('\n').trim() };
}

/** The release notes for `version`, or throw with a reason. */
export function releaseNotes(text, version, { allowUnreleased = false } = {}) {
  const section = changelogSection(text, version);
  if (!section) throw new Error(`CHANGELOG.md has no "## [${version}]" section`);
  if (!allowUnreleased && /unreleased/i.test(section.heading)) {
    throw new Error(`CHANGELOG.md still marks ${version} as unreleased; put the release date in its heading`);
  }
  if (!section.body) throw new Error(`CHANGELOG.md section for ${version} is empty`);
  return `${section.body}\n`;
}

function main(argv) {
  const allowUnreleased = argv.includes('--allow-unreleased');
  const rest = argv.filter((a) => a !== '--allow-unreleased');
  if (rest.length !== 1) {
    process.stderr.write('usage: release-notes.mjs <version> [--allow-unreleased]\n');
    return 1;
  }
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  try {
    const text = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
    process.stdout.write(releaseNotes(text, rest[0], { allowUnreleased }));
    return 0;
  } catch (err) {
    process.stderr.write(`release-notes: ${err.message}\n`);
    return 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
