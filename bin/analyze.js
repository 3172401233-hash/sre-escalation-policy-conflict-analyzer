#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { analyze } from '../src/engine.js';

const file = process.argv[2];
if (!file) {
  console.error('usage: node bin/analyze.js <scenario.json>');
  process.exit(1);
}

const input = JSON.parse(await readFile(file, 'utf8'));
const plan = analyze(input);

// This tool only computes a plan. It never sends real notifications.
process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
