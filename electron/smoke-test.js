const { app, BrowserWindow, Menu } = require('electron');
const path = require('path');
const { menuTemplate } = require('./main.js');

const timeout = setTimeout(() => {
  console.error('Electron smoke test timed out');
  app.exit(1);
}, 30000);

async function main() {
  await app.whenReady();

  const menu = Menu.buildFromTemplate(menuTemplate);
  const security = menu.items.find((item) => item.label === 'Security');
  const securityLabels = security.submenu.items.map((item) => item.label);
  for (const expected of [
    'Copy intended recipient key',
    'Copy faux key',
    'Clear clipboard',
    'Clear all fields + clipboard',
  ]) {
    if (!securityLabels.includes(expected)) {
      throw new Error(`Missing Electron Security menu item: ${expected}`);
    }
  }

  const window = new BrowserWindow({
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
  });
  await window.loadFile(path.join(__dirname, 'src', 'index.html'));
  const result = await window.webContents.executeJavaScript(`
    (() => {
      const keyA = 'K6:0 000 0 013';
      const keyB = 'K6:1 102103 0 050';
      const standard = window.ENIGMAK.encrypt('ELECTRON STANDARD', keyA);
      const standardResult = window.ENIGMAK.decrypt(standard, keyA);
      const dual = window.ENIGMAK.encryptDualMessage(
        'ELECTRON INTENDED',
        'ELECTRON FAUX',
        {
          realKeyStr: keyA,
          fauxKeyStr: keyB,
          envelopeNonce: Uint8Array.from([...Array(16).keys()]),
        },
      );
      const real = window.ENIGMAK.decrypt(dual.ciphertext, keyA);
      const faux = window.ENIGMAK.decrypt(dual.ciphertext, keyB);
      return {
        runtime: !!window.ENIGMAK,
        sandboxed: typeof require === 'undefined',
        controls: !!document.getElementById('faux-input')
          && !!document.getElementById('dual-intended-key-val')
          && !!document.getElementById('dual-faux-key-val'),
        standard: standardResult.verified
          && standardResult.plaintext === 'ELECTRON STANDARD',
        real: real.verified && real.plaintext === 'ELECTRON INTENDED',
        faux: faux.verified && faux.plaintext === 'ELECTRON FAUX',
      };
    })()
  `);
  if (Object.values(result).some((value) => value !== true)) {
    throw new Error(`Electron renderer smoke failure: ${JSON.stringify(result)}`);
  }
  window.destroy();
  clearTimeout(timeout);
  console.log('Electron startup, sandbox, menu, and dual renderer checks passed');
  app.quit();
}

main().catch((error) => {
  clearTimeout(timeout);
  console.error(error);
  app.exit(1);
});
