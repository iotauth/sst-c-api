#!/usr/bin/env node

// Usage: ./configGenerator.js <count>

// Examples: ./configGenerator.js 100

const fs = require('fs');
const path = require('path');

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

const client_template_tcp = '../config/client.config';
const client_template_udp = '../config/client_udp.config';
const out_dir = '../config_clones';

function loadTemplate(templatePath) {
  try {
    return fs.readFileSync(templatePath, 'utf8').split(/\r?\n/);
  } catch (err) {
    console.error(
      `Failed to read the template client config \"${templatePath}\": ${err.message}`
    );
    process.exit(1);
  }
}

const tcpLines = loadTemplate(client_template_tcp);
const udpLines = loadTemplate(client_template_udp);

// Create the output config folder
if (!fs.existsSync(out_dir)) {
  fs.mkdirSync(out_dir, { recursive: true });
}

// remove old configs
fs.readdirSync(out_dir).forEach(file => {
  if (file.endsWith('.config')) {
    fs.unlinkSync(path.join(out_dir, file));
  }
});

function makeConfigLines(lines, i) {
  const client_name = `net1.client${i}`;
  const key_filename = `Net1.Client${i}Key.pem`;
  return lines.map(line => {
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
}

// Output the new TCP + UDP config files
for (let i = 0; i < count; i++) {
  const tcpOutPath = path.join(out_dir, `client${i}.config`);
  const udpOutPath = path.join(out_dir, `client${i}_udp.config`);
  fs.writeFileSync(tcpOutPath, makeConfigLines(tcpLines, i).join('\n'), 'utf8');
  fs.writeFileSync(udpOutPath, makeConfigLines(udpLines, i).join('\n'), 'utf8');
}

console.log(
  `Generated ${count} TCP and ${count} UDP configs in SST_Testbed/config_clones/`
);
