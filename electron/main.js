const { app, BrowserWindow, Menu, shell, dialog, clipboard } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 960,
    height: 860,
    minWidth: 700,
    minHeight: 600,
    title: 'ENIGMAK',
    backgroundColor: '#080c08',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    autoHideMenuBar: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));

  mainWindow.on('closed', () => { mainWindow = null; });
}

const menuTemplate = [
  {
    label: 'File',
    submenu: [
      {
        label: 'Save ciphertext…',
        accelerator: 'CmdOrCtrl+S',
        click: async () => {
          if (!mainWindow) return;
          const result = await mainWindow.webContents.executeJavaScript(
            'document.getElementById("output").value'
          );
          if (!result) return;
          const { filePath } = await dialog.showSaveDialog(mainWindow, {
            title: 'Save ciphertext',
            defaultPath: 'enigmak-output.txt',
            filters: [{ name: 'Text files', extensions: ['txt'] }],
          });
          if (filePath) fs.writeFileSync(filePath, result, 'utf8');
        },
      },
      {
        label: 'Load message…',
        accelerator: 'CmdOrCtrl+O',
        click: async () => {
          if (!mainWindow) return;
          const { filePaths } = await dialog.showOpenDialog(mainWindow, {
            title: 'Load message',
            filters: [{ name: 'Text files', extensions: ['txt'] }],
            properties: ['openFile'],
          });
          if (!filePaths || !filePaths[0]) return;
          const text = fs.readFileSync(filePaths[0], 'utf8');
          await mainWindow.webContents.executeJavaScript(
            `document.getElementById('input').value = ${JSON.stringify(text)}; onInput();`
          );
        },
      },
      { type: 'separator' },
      { role: 'quit' },
    ],
  },
  {
    label: 'Edit',
    submenu: [
      { role: 'undo' },
      { role: 'redo' },
      { type: 'separator' },
      { role: 'cut' },
      { role: 'copy' },
      { role: 'paste' },
      { role: 'selectAll' },
      { type: 'separator' },
      {
        label: 'Clear all',
        accelerator: 'CmdOrCtrl+Shift+X',
        click: async () => {
          if (!mainWindow) return;
          await mainWindow.webContents.executeJavaScript(
            `document.getElementById('input').value='';
             document.getElementById('output').value='';
             onInput();`
          );
        },
      },
    ],
  },
  {
    label: 'View',
    submenu: [
      { role: 'reload' },
      { type: 'separator' },
      { role: 'zoomIn' },
      { role: 'zoomOut' },
      { role: 'resetZoom' },
      { type: 'separator' },
      { role: 'togglefullscreen' },
    ],
  },
  {
    label: 'Security',
    submenu: [
      {
        label: 'Clear clipboard',
        click: () => { clipboard.writeText(''); },
      },
      {
        label: 'Clear all fields + clipboard',
        accelerator: 'CmdOrCtrl+Shift+Delete',
        click: async () => {
          clipboard.writeText('');
          if (!mainWindow) return;
          await mainWindow.webContents.executeJavaScript(
            `document.getElementById('input').value='';
             document.getElementById('output').value='';
             document.getElementById('key-import').value='';
             onInput();`
          );
        },
      },
    ],
  },
  {
    label: 'Help',
    submenu: [
      {
        label: 'About ENIGMAK',
        click: () => {
          dialog.showMessageBox(mainWindow, {
            type: 'info',
            title: 'About ENIGMAK',
            message: 'ENIGMAK v3.0.0-rc.4',
            detail:
              'Custom rotor cipher machine\n' +
              '95-symbol alphabet - 1-13 rotors - Steckerbrett\n' +
              'Irregular stepping - diffusion - key-derived layouts\n' +
              '1-999 key-derived rounds - position whitening\n' +
              'Hidden metadata format - zero-width carrier encoding\n\n' +
              'Keyspace: ~4.528 x 10^128\n' +
              'Runs fully offline - no network requests.',
          });
        },
      },
    ],
  },
];

app.whenReady().then(() => {
  createWindow();
  const menu = Menu.buildFromTemplate(menuTemplate);
  Menu.setApplicationMenu(menu);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Block all external navigation
app.on('web-contents-created', (_, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});
