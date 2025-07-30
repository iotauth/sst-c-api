#!/usr/bin/env node

// Usage: ./configGenerator.js <count>

// Examples: ./configGenerator.js 100

import fs   from 'fs';
import path from 'path';

// Parses the command line arguments
const args = process.argv.slice(2);
if (args.length !== 1) {
  console.error('Usage: config_generator.js <count>');
  process.exit(1);
}

const count = parseInt(args[0], 10);
if (isNaN(count) || count < 1) {
  console.error('Error: <count> must be a positive integer.');
  process.exit(1);
}

const original_config = '../../server_client_example/c_client.config';
const out_dir = '../config';

if (isNaN(count) || count < 1) {
  console.error('Error: <count> must be a positive integer.');
  process.exit(1);
}

// // Read the input .graph file
let lines;
try {
  lines = fs.readFileSync(original_config, 'utf8').split(/\r?\n/);
} catch (err) {
  console.error(`Failed to read the original config \"${original_config}\": ${err.message}`);
  process.exit(1);
}

// // Create the output config folder
if (!fs.existsSync(out_dir)) {
  fs.mkdirSync(out_dir, { recursive: true });
}

// remove old configs
fs.readdirSync(out_dir).forEach(file => {
  if (file.endsWith('.config')) {
    fs.unlinkSync(path.join(out_dir, file));
  }
});

// Output the new config files
for (let i = 0; i < count; i++) {
  const client_name = `net1.client${i}`;
  const key_filename = `Net1.Client${i}Key.pem`;
  const out_lines = lines.map(line => {
    if (line.startsWith('entityInfo.name=')) {
      // add the client # to the client name
      return `entityInfo.name=${client_name}`;
    }
    if (line.startsWith('entityInfo.privkey.path=')) {
      // add the client # to the key path
      const original = line.split('=')[1];
      const prefix = original.substring(0, original.lastIndexOf('/') + 1);
      return `entityInfo.privkey.path=${prefix}${key_filename}`;
    }
    return line;
  });

  const out_path = path.join(out_dir, `client${i}.config`);
  fs.writeFileSync(out_path, out_lines.join('\n'), 'utf8');
}

console.log(`Generated ${count} configs in scenario_example/config/`);
