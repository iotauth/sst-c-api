#!/usr/bin/env node

// Usage: ./graphGenerator.js <count>

// Examples: ./graphGenerator.js 50

const fs   = require('fs');
const path = require('path');

// Parses the command line arguments
const args = process.argv.slice(2);
if (args.length !== 1) {
  console.error('Usage: graph_generator.js <count>');
  process.exit(1);
}

const count = parseInt(args[0], 10);
if (isNaN(count) || count < 1) {
  console.error('Error: <count> must be a positive integer.');
  process.exit(1);
}

const default_graph = '../../../../../examples/configs/default.graph';
const output = '../../../../../examples/configs/custom_clients.graph';

// Read the .graph file
let data;
try {
  data = JSON.parse(fs.readFileSync(default_graph, 'utf8'));
} catch (err) {
  console.error(`Failed to read "${default_graph}":`, err.message);
  process.exit(1);
}

// Change the assignments
const base_key = 'net1.client';
const authId  = data.assignments[base_key];
if (authId === undefined) {
  console.error(`Key "${base_key}" not found in assignments.`);
  process.exit(1);
}
delete data.assignments[base_key];
for (let i = 0; i < count; i++) {
  data.assignments[`${base_key}${i}`] = authId;
}

// Change the entityList
const new_entities = [];
for (const ent of data.entityList) {
  if (ent.name === base_key) {
    for (let i = 0; i < count; i++) {
      const copy = JSON.parse(JSON.stringify(ent));
      copy.name = `${base_key}${i}`;
      if (copy.credentialPrefix) {
        copy.credentialPrefix = `Net1.Client${i}`;
      }
      new_entities.push(copy);
    }
  } else {
    new_entities.push(ent);
  }
}
data.entityList = new_entities;

fs.writeFileSync(output, JSON.stringify(data, null, 4), 'utf8');
console.log(`Generated the new graph file with ${count} client entries.`);
