// Exercise the exact browser ZIP builder without a browser or network dependency.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { File } = require('node:buffer');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'lens/web/app.js'), 'utf8');
const start = source.indexOf('function crc32(');
const end = source.indexOf("$('demo').addEventListener", start);
assert.ok(start >= 0 && end > start);
const context = vm.createContext({TextEncoder, File, Uint8Array, DataView});
vm.runInContext(source.slice(start, end), context);
assert.equal(vm.runInContext("crc32(new TextEncoder().encode('123456789'))", context), 0xcbf43926);
(async () => {
  const file = vm.runInContext('trainingZip()', context);
  assert.equal(file.name, 'ghostlayer-training.zip');
  const data = Buffer.from(await file.arrayBuffer());
  assert.equal(data.readUInt32LE(0), 0x04034b50);
  assert.equal(data.readUInt16LE(data.length - 22 + 10), 4);
  const destination = process.argv[2];
  if (destination) fs.writeFileSync(destination, data, {flag:'wx'});
  console.log('Browser ZIP builder passed CRC32 and inventory checks.');
})().catch(error => {console.error(error);process.exitCode = 1;});
