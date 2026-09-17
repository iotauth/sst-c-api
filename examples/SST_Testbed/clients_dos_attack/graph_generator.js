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

const clientTypes = [
  {
    baseKey: 'net1.client',
    credentialPrefix: 'Net1.Client'
  },
  {
    baseKey: 'net1.udpClient',
    credentialPrefix: 'Net1.UdpClient'
  }
];

// Change the assignments
for (const clientType of clientTypes) {
  const authId = data.assignments[clientType.baseKey];
  if (authId === undefined) {
    console.error(`Key "${clientType.baseKey}" not found in assignments.`);
    process.exit(1);
  }

  delete data.assignments[clientType.baseKey];
  for (let i = 0; i < count; i++) {
    data.assignments[`${clientType.baseKey}${i}`] = authId;
  }
}

// Change the entityList
const new_entities = [];
for (const ent of data.entityList) {
  const clientType = clientTypes.find(type => type.baseKey === ent.name);
  if (clientType) {
    for (let i = 0; i < count; i++) {
      const copy = JSON.parse(JSON.stringify(ent));
      copy.name = `${clientType.baseKey}${i}`;
      if (copy.credentialPrefix) {
        copy.credentialPrefix = `${clientType.credentialPrefix}${i}`;
      }
      new_entities.push(copy);
    }
  } else {
    new_entities.push(ent);
  }
}
data.entityList = new_entities;

fs.writeFileSync(output, JSON.stringify(data, null, 4), 'utf8');
console.log(`Generated the new graph file with ${count} TCP and ${count} UDP client entries.`);
