import { app, Menu, Tray, BrowserWindow, nativeImage } from 'electron';
import * as path from 'node:path';

let tray: Tray | null = null;

export type VaultStatus = 'locked' | 'unlocked' | 'error' | 'disconnected';

export function createTray(mainWindow: BrowserWindow): Tray {
  const iconPath = path.join(__dirname, '..', '..', 'assets', 'icon.ico');
  const icon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });

  tray = new Tray(icon);
  tray.setToolTip('SovereignKernel Vault — Vergrendeld');

  updateTrayMenu('locked', mainWindow);

  tray.on('double-click', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  return tray;
}

export function updateTrayStatus(status: VaultStatus): void {
  if (!tray) return;
  const tooltips: Record<VaultStatus, string> = {
    locked: 'SovereignKernel Vault — Vergrendeld 🔒',
    unlocked: 'SovereignKernel Vault — Ontgrendeld 🔓',
    error: 'SovereignKernel Vault — Fout ⚠️',
    disconnected: 'SovereignKernel Vault — Geen verbinding',
  };
  tray.setToolTip(tooltips[status]);
}

export function updateTrayMenu(status: VaultStatus, mainWindow: BrowserWindow): void {
  if (!tray) return;

  const contextMenu = Menu.buildFromTemplate([
    {
      label: `Status: ${status === 'locked' ? 'Vergrendeld' : status === 'unlocked' ? 'Ontgrendeld' : status === 'error' ? 'Fout' : 'Geen verbinding'}`,
      enabled: false,
    },
    { type: 'separator' },
    {
      label: 'Vault openen',
      click: () => { mainWindow.show(); mainWindow.focus(); },
    },
    {
      label: 'Vergrendelen',
      enabled: status === 'unlocked',
      click: () => { mainWindow.webContents.send('vault:lock-request'); },
    },
    { type: 'separator' },
    {
      label: 'Backup maken',
      click: () => { mainWindow.webContents.send('vault:backup-request'); },
    },
    { type: 'separator' },
    {
      label: 'Afsluiten',
      click: () => {
        mainWindow.webContents.send('vault:shutdown');
        setTimeout(() => app.quit(), 1000);
      },
    },
  ]);

  tray.setContextMenu(contextMenu);
  updateTrayStatus(status);
}

export function destroyTray(): void {
  if (tray) {
    tray.destroy();
    tray = null;
  }
}
