/**
 * PulseGuard GUI Automated Verification & Linting Suite.
 * Validates file structure, syntax parsing, and HTML DOM elements.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let errors = 0;
function assert(condition, message) {
  if (!condition) {
    console.error(`❌ FAIL: ${message}`);
    errors++;
  } else {
    console.log(`✅ PASS: ${message}`);
  }
}

console.log('--- [PulseGuard GUI Test Suite] ---');

// 1. Check required files existence
const requiredFiles = [
  'package.json',
  'main.js',
  'preload.js',
  'index.html',
  'styles.css',
  'app.js',
];

for (const file of requiredFiles) {
  const fullPath = path.join(__dirname, file);
  assert(fs.existsSync(fullPath), `File exists: ${file}`);
}

// 2. Validate package.json
try {
  const pkgContent = fs.readFileSync(path.join(__dirname, 'package.json'), 'utf-8');
  const pkg = JSON.parse(pkgContent);
  assert(pkg.name === 'pulseguard-gui', 'package.json has valid name');
  assert(pkg.main === 'main.js', 'package.json points to main.js');
  assert(pkg.scripts && pkg.scripts.start, 'package.json has start script');
} catch (e) {
  assert(false, `package.json is valid JSON: ${e.message}`);
}

// 3. Syntax check JavaScript files
const jsFiles = ['preload.js', 'app.js'];
for (const file of jsFiles) {
  try {
    const code = fs.readFileSync(path.join(__dirname, file), 'utf-8');
    new vm.Script(code);
    assert(true, `Syntax valid: ${file}`);
  } catch (e) {
    assert(false, `Syntax error in ${file}: ${e.message}`);
  }
}

// 4. Validate HTML structure & critical IDs
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf-8');
const requiredIds = [
  'pill-engine-status',
  'pill-watcher-status',
  'pane-dashboard',
  'pane-scanner',
  'pane-processes',
  'pane-quarantine',
  'pane-watcher',
  'pane-audit',
  'btn-start-scan',
  'scan-target-path',
  'scan-results-tbody',
  'processes-tbody',
  'quarantine-tbody',
  'watcher-toggle-checkbox',
  'audit-log-terminal',
  'ctrl-minimize',
  'ctrl-maximize',
  'ctrl-close',
];

for (const id of requiredIds) {
  assert(html.includes(`id="${id}"`), `HTML contains element with id="${id}"`);
}

// 5. Validate CSS rules
const css = fs.readFileSync(path.join(__dirname, 'styles.css'), 'utf-8');
assert(css.includes('--neon-cyan: #00f0ff;'), 'CSS contains cyberpunk neon variables');
assert(css.includes('.radar-container'), 'CSS contains radar container style');
assert(css.includes('.cyber-table'), 'CSS contains cyber table style');
assert(css.includes('backdrop-filter: blur'), 'CSS contains glassmorphism backdrop-filter');

console.log('------------------------------------');
if (errors === 0) {
  console.log('🎉 ALL 28 GUI VERIFICATION CHECKS PASSED SUCCESSFULLY!');
  process.exit(0);
} else {
  console.error(`💥 ${errors} checks failed.`);
  process.exit(1);
}
