import { app, BrowserWindow, ipcMain, dialog, Notification } from 'electron';
import * as path from 'node:path';
import { IpcClient } from './ipc-client';

let mainWindow: BrowserWindow | null = null;
let vaultClient: IpcClient | null = null;

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: 'SovereignKernel Vault',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
    show: false,
  });

  mainWindow.once('ready-to-show', () => mainWindow?.show());

  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }

  mainWindow.on('closed', () => { mainWindow = null; });
}

async function initVaultConnection(): Promise<void> {
  vaultClient = new IpcClient();
  vaultClient.on('connected', () => {
    mainWindow?.webContents.send('vault:connected');
  });
  vaultClient.on('disconnected', () => {
    mainWindow?.webContents.send('vault:disconnected');
  });
  vaultClient.on('error', (err: Error) => {
    mainWindow?.webContents.send('vault:error', err.message);
  });

  try {
    await vaultClient.connect();
  } catch {
    mainWindow?.webContents.send('vault:error', 'Kan niet verbinden met vault service');
  }
}

function registerIpcHandlers(): void {
  ipcMain.handle('vault:status', async () => {
    if (!vaultClient?.connected) return { ok: false, error: 'Niet verbonden' };
    try {
      const res = await vaultClient.send('status');
      return { ok: true, data: JSON.parse(res.toString()) };
    } catch (e: unknown) {
      return { ok: false, error: (e as Error).message };
    }
  });

  ipcMain.handle('vault:unlock', async (_event, provider: string) => {
    if (!vaultClient?.connected) return { ok: false, error: 'Niet verbonden' };
    try {
      const res = await vaultClient.send('unlock', { provider });
      return { ok: true, data: JSON.parse(res.toString()) };
    } catch (e: unknown) {
      return { ok: false, error: (e as Error).message };
    }
  });

  ipcMain.handle('vault:lock', async () => {
    if (!vaultClient?.connected) return { ok: false, error: 'Niet verbonden' };
    try {
      const res = await vaultClient.send('lock');
      return { ok: true, data: JSON.parse(res.toString()) };
    } catch (e: unknown) {
      return { ok: false, error: (e as Error).message };
    }
  });

  ipcMain.handle('ui:confirm', async (_event, title: string, message: string) => {
    const result = await dialog.showMessageBox(mainWindow!, {
      type: 'question',
      buttons: ['Annuleren', 'Doorgaan'],
      defaultId: 0,
      cancelId: 0,
      title,
      message,
    });
    return { proceed: result.response === 1 };
  });

  ipcMain.handle('ui:notification', async (_event, title: string, body: string) => {
    new Notification({ title, body }).show();
  });
}

app.whenReady().then(async () => {
  createWindow();
  registerIpcHandlers();
  await initVaultConnection();
});

app.on('window-all-closed', () => {
  vaultClient?.disconnect();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
