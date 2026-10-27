/**
 * PulseGuard Electron Main Process Entrypoint.
 * Manages window lifecycle, native dialog IPC, and backend service supervision.
 */

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const http = require('http');

let mainWindow = null;
let pythonProcess = null;
const BACKEND_PORT = 48201;
const BACKEND_HOST = '127.0.0.1';

/**
 * Robustly finds the PulseGuard repository root containing src/pulseguard.
 */
function findRepoRoot() {
  const candidates = [
    path.resolve(__dirname, '..'),
    path.resolve(__dirname, '../../..'),
    process.cwd(),
    path.resolve(process.resourcesPath || __dirname, '../../..'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'src', 'pulseguard'))) {
      return c;
    }
  }
  return path.resolve(__dirname, '..');
}

/**
 * Checks if the PulseGuard Python backend server is responding.
 * @returns {Promise<boolean>}
 */
function isBackendAlive() {
  return new Promise((resolve) => {
    const req = http.get(
      {
        host: BACKEND_HOST,
        port: BACKEND_PORT,
        path: '/api/status',
        timeout: 1000,
      },
      (res) => {
        resolve(res.statusCode === 200);
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

/**
 * Automatically launches the PulseGuard Python API backend if not active.
 */
async function ensureBackendRunning() {
  const alive = await isBackendAlive();
  if (alive) {
    console.log('[PulseGuard Main] Python backend already active on port', BACKEND_PORT);
    return;
  }

  const repoRoot = findRepoRoot();
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
  const env = {
    ...process.env,
    PYTHONPATH: path.join(repoRoot, 'src'),
    PYTHONIOENCODING: 'utf-8',
  };

  console.log('[PulseGuard Main] Spawning Python API backend:', pythonCmd, '-m pulseguard serve');
  pythonProcess = spawn(pythonCmd, ['-m', 'pulseguard', 'serve', '--port', String(BACKEND_PORT)], {
    cwd: repoRoot,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    shell: process.platform === 'win32',
  });

  pythonProcess.stdout.on('data', (data) => {
    console.log(`[Python API] ${data.toString().trim()}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`[Python API Error] ${data.toString().trim()}`);
  });

  pythonProcess.on('exit', (code, sig) => {
    console.log(`[PulseGuard Main] Python backend exited with code ${code}, signal ${sig}`);
    pythonProcess = null;
  });

  // Wait briefly for server to bind
  for (let i = 0; i < 15; i++) {
    await new Promise((r) => setTimeout(r, 300));
    if (await isBackendAlive()) {
      console.log('[PulseGuard Main] Python API bridge confirmed connected!');
      break;
    }
  }
}

/**
 * Creates the primary application window with a Cyberpunk Glassmorphism canvas.
 */
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1240,
    height: 840,
    minWidth: 1000,
    minHeight: 680,
    title: 'PulseGuard Total Security',
    backgroundColor: '#07090e',
    show: false,
    frame: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Window control IPC handlers (Minimize, Maximize, Close)
ipcMain.on('window:minimize', () => {
  if (mainWindow) mainWindow.minimize();
});

ipcMain.on('window:maximize', () => {
  if (mainWindow) {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  }
});

ipcMain.on('window:close', () => {
  if (mainWindow) mainWindow.close();
});

// Register native file/directory dialog IPC handlers
ipcMain.handle('dialog:select-file', async () => {
  if (!mainWindow) return null;
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'PulseGuard — Sélectionner un fichier à analyser',
    properties: ['openFile'],
  });
  if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0];
});

ipcMain.handle('dialog:select-directory', async () => {
  if (!mainWindow) return null;
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'PulseGuard — Sélectionner un dossier à analyser ou surveiller',
    properties: ['openDirectory'],
  });
  if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0];
});

app.whenReady().then(async () => {
  try {
    await ensureBackendRunning();
  } catch (err) {
    console.error('[PulseGuard Main] Failed to initialize backend:', err);
  }
  createMainWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on('will-quit', () => {
  if (pythonProcess) {
    console.log('[PulseGuard Main] Terminating spawned Python backend process...');
    pythonProcess.kill('SIGTERM');
    pythonProcess = null;
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
