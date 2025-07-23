#!/usr/bin/env node
/*
 * Usage: ./entityGenerator.js --count 100 [--input default.graph] [--output customClients.graph]
 */

import fs    from 'fs';
import path  from 'path';
import { Command } from 'commander';

const program = new Command();
program
  .requiredOption('-n, --count <number>',  'how many client variants to generate', parseInt)
  .option       ('-i, --input <file>',     'input .graph file',   '../../../../examples/configs/default.graph')
  .option       ('-o, --output <file>',    'output .graph file',  '../../../../examples/configs/customClients.graph')
  .parse(process.argv);

const { count, input, output } = program.opts();

// Load the default .graph file
let data;
try {
  data = JSON.parse(fs.readFileSync(input, 'utf8'));
} catch (err) {
  console.error(`Failed to read or parse ${input}:`, err.message);
  process.exit(1);
}

// Extract authId for net1.client, remove base assignment
const baseKey = 'net1.client';
const authId  = data.assignments[baseKey];
if (authId === undefined) {
  console.error(`"${baseKey}" not found in assignments.`);
  process.exit(1);
}
delete data.assignments[baseKey];

// Generate the assignments for all the new clients
for (let i = 0; i < count; i++) {
  data.assignments[`${baseKey}${i}`] = authId;
}

// 4) Replace the net1.client entityList entries
const newEntities = [];
for (const ent of data.entityList) {
  if (ent.name === baseKey) {
    for (let i = 0; i < count; i++) {
      const copy = JSON.parse(JSON.stringify(ent));
      copy.name             = `${baseKey}${i}`;
      if (copy.credentialPrefix)
        copy.credentialPrefix = `Net1.Client${i}`;
      newEntities.push(copy);
    }
  } else {
    newEntities.push(ent);
  }
}
data.entityList = newEntities;

// 5) Write out JSON
fs.writeFileSync(output,
  JSON.stringify(data, null, 4),
  'utf8'
);

console.log(`Wrote ${output} with ${count} net1.client entries.`);
