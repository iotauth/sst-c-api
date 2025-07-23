#!/usr/bin/env node
/*
 * Usage: ./configGenerator.js --count 100 [--template c_client.config] [--out-dir config]
 */

import fs   from 'fs';
import path from 'path';
import { Command } from 'commander';

const program = new Command();
program
  .requiredOption('-n, --count <number>', 'how many config files to generate', parseInt)
  .option       ('-t, --template <file>',  'template config file', '../server_client_example/c_client.config')
  .option       ('-o, --out-dir <dir>',    'output directory',      'config')
  .parse(process.argv);

const { count, template, outDir } = program.opts();

// Read the template
let lines;
try {
  lines = fs.readFileSync(template, 'utf8').split(/\r?\n/);
} catch (err) {
  console.error(`Cannot read template ${template}:`, err.message);
  process.exit(1);
}

// Create the output config folder
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
// remove old configs
for (const fname of fs.readdirSync(outDir)) {
  if (fname.endsWith('.config'))
    fs.unlinkSync(path.join(outDir, fname));
}

// Output the new config files
for (let i = 0; i < count; i++) {
  const outLines = lines.map((line, idx) =>
    idx === 0 && line.startsWith('entityInfo.name=')
      ? `entityInfo.name=net1.client${i}`
      : line
  );
  fs.writeFileSync(
    path.join(outDir, `client${i}.config`),
    outLines.join('\n'),
    'utf8'
  );
}

console.log(`Generated ${count} configs in ./${outDir}/`);
