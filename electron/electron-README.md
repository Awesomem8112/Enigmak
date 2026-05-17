# ENIGMAK Desktop App

This folder contains the Electron wrapper for the ENIGMAK `v3.0.0-rc.5`
machine.

## Requirements

- Node.js 18 or later
- npm

## Quick Start

```bash
npm install
npm start
```

This launches ENIGMAK as a native desktop window with the same `rc.4-hidden`
wire-compatible runtime bundle used by the root browser build.

## Build Outputs

Windows portable executable:

```bash
npm run build-win
```

Linux AppImage:

```bash
npm run build-linux
```

macOS DMG:

```bash
npm run build-mac
```

## What The Wrapper Adds

- File menu actions for saving ciphertext and loading text files
- standard edit actions
- clipboard clearing shortcuts
- a native About dialog
- native window controls
- blocked external navigation

## Structure

```text
electron/
  main.js
  package.json
  package-lock.json
  src/index.html
```

`src/index.html` is the mirrored machine UI used by the desktop build. It is
kept in sync with the root `enigmak.html`, including the active
`rc.4-hidden` browser runtime.

## Security Notes

- `nodeIntegration` is disabled
- `contextIsolation` is enabled
- `sandbox` is enabled
- all external navigation is blocked
- the app makes no network requests on its own
