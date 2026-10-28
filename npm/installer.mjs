#!/usr/bin/env node
// Entry point of `npx claude-multi-auth` / `claude-multi-auth`. Everything
// lives in lib/installer.mjs; see the comment at its top.
import { main } from './lib/installer.mjs';

// If the reader of our output goes away (`claude-multi-auth ... | head`),
// keep going: stopping halfway through an install would be worse than
// losing the rest of the messages.
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (err) => {
    if (err.code !== 'EPIPE') throw err;
  });
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`claude-multi-auth: ${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  },
);
