/**
 * PulseGuard Electron Preload Script.
 * Securely bridges native dialogs and environment information to the renderer.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pulseguard', {
  /**
   * Prompts native Windows file picker dialog.
   * @returns {Promise<string|null>} Selected file path or null.
   */
  selectFile: () => ipcRenderer.invoke('dialog:select-file'),

  /**
   * Prompts native Windows directory picker dialog.
   * @returns {Promise<string|null>} Selected folder path or null.
   */
  selectDirectory: () => ipcRenderer.invoke('dialog:select-directory'),

  /**
   * Returns default backend API base URL.
   */
  backendUrl: 'http://127.0.0.1:48201',

  /**
   * Platform identifier.
   */
  platform: process.platform,

  /**
   * Frameless Window Controls (Bitdefender-style)
   */
  minimize: () => ipcRenderer.send('window:minimize'),
  maximize: () => ipcRenderer.send('window:maximize'),
  close: () => ipcRenderer.send('window:close'),
});
