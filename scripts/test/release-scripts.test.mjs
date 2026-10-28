// Tests for the release helper scripts (pure parts only).
import assert from 'node:assert/strict';
import test from 'node:test';

import { cargoWorkspaceVersion, findMismatches, versionFromTag } from '../check-versions.mjs';
import { changelogSection, releaseNotes } from '../release-notes.mjs';

test('cargoWorkspaceVersion reads only [workspace.package]', () => {
  const toml = '[package]\nversion = "9.9.9"\n\n[workspace.package]\nedition = "2024"\nversion = "1.2.3"\n\n[x]\nversion = "0"\n';
  assert.equal(cargoWorkspaceVersion(toml), '1.2.3');
  assert.equal(cargoWorkspaceVersion('[package]\nversion = "1"\n'), null);
});

test('versionFromTag accepts vX.Y.Z tags only', () => {
  assert.equal(versionFromTag('v1.2.3'), '1.2.3');
  assert.equal(versionFromTag('refs/tags/v1.2.3-rc.1'), '1.2.3-rc.1');
  assert.equal(versionFromTag('1.2.3'), null);
  assert.equal(versionFromTag('vnext'), null);
});

test('findMismatches compares every file with the tag or the first entry', () => {
  const ok = [['a', '1.0.0'], ['b', '1.0.0']];
  assert.deepEqual(findMismatches(ok), []);
  assert.deepEqual(findMismatches(ok, '1.0.0'), []);
  assert.deepEqual(findMismatches(ok, '1.0.1'), ['a is 1.0.0, expected 1.0.1', 'b is 1.0.0, expected 1.0.1']);
  assert.deepEqual(findMismatches([['a', '1.0.0'], ['b', undefined]]), ['b is (missing), expected 1.0.0']);
});

const CHANGELOG = `# Changelog

## [1.1.0] - 2026-11-02

### Added

- Thing.

## [1.0.0] - unreleased

- First.

[1.1.0]: https://example.invalid/1.1.0
`;

test('changelogSection returns the heading and body of one version', () => {
  assert.deepEqual(changelogSection(CHANGELOG, '1.1.0'), {
    heading: '## [1.1.0] - 2026-11-02',
    body: '### Added\n\n- Thing.',
  });
  assert.equal(changelogSection(CHANGELOG, '1.0.0').body, '- First.');
  assert.equal(changelogSection(CHANGELOG, '2.0.0'), null);
  // A prefix of another version does not match.
  assert.equal(changelogSection(CHANGELOG, '1.1'), null);
});

test('releaseNotes refuses unreleased and missing sections', () => {
  assert.equal(releaseNotes(CHANGELOG, '1.1.0'), '### Added\n\n- Thing.\n');
  assert.throws(() => releaseNotes(CHANGELOG, '1.0.0'), /unreleased/);
  assert.equal(releaseNotes(CHANGELOG, '1.0.0', { allowUnreleased: true }), '- First.\n');
  assert.throws(() => releaseNotes(CHANGELOG, '3.0.0'), /no "## \[3\.0\.0\]" section/);
  assert.throws(() => releaseNotes('## [1.0.0] - 2026-01-01\n\n## [0.9.0]\n', '1.0.0'), /empty/);
});
