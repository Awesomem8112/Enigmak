# ENIGMAK - Desktop App

Standalone offline desktop application wrapping the ENIGMAK cipher machine in Electron.

## Requirements

- Node.js 18 or later (https://nodejs.org)
- npm (included with Node.js)

## Quick start (run without building)

```bash
npm install
npm start
```

This opens ENIGMAK as a native desktop window. No browser needed, fully offline.

## Build a distributable

### Windows (portable .exe - no installer needed)
```bash
npm run build-win
```
Output: `dist/ENIGMAK*.exe`

### Linux (AppImage - runs on any distro)
```bash
npm run build-linux
```
Output: `dist/ENIGMAK*.AppImage`

### macOS (dmg)
```bash
npm run build-mac
```
Output: `dist/ENIGMAK*.dmg`

## Features added by the desktop wrapper

- **File menu** - save ciphertext to .txt, load message from .txt
- **Security menu** - clear clipboard, clear all fields + clipboard in one keystroke (Ctrl+Shift+Delete)
- **Edit menu** - standard cut/copy/paste + clear all fields
- **About dialog** - version and keyspace info
- **Fully air-gappable** - no network requests, ever. All external navigation blocked.
- **Native window** - zoom in/out, fullscreen, proper OS title bar

## Structure

```
enigmak-electron/
├── main.js          - Electron main process (window, menus, file I/O)
├── package.json     - build config
├── electron-README.md        - this file
└── src/
    └── index.html   - the full ENIGMAK machine (unchanged)
```

## Security notes

- `nodeIntegration` is disabled - the cipher page has no access to Node.js APIs
- `contextIsolation` and `sandbox` are enabled
- All external navigation (links, window.open) is blocked at the app level
- The app makes zero network requests
