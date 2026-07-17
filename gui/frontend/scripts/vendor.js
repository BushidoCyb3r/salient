import { copyFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

const source = resolve('../../web');
const names = readdirSync(source).filter((name) => name.endsWith('.js'));
const check = process.argv.includes('--check');
const target = resolve(check ? 'dist/vendor' : 'public/vendor');

if (names.length === 0) throw new Error('no vendored JavaScript found');
if (!check) mkdirSync(target, { recursive: true });
for (const name of names) {
  const origin = resolve(source, name);
  const destination = resolve(target, name);
  if (check) {
    if (statSync(destination).size !== statSync(origin).size) {
      throw new Error(`vendor asset mismatch: ${name}`);
    }
  } else {
    copyFileSync(origin, destination);
  }
}
