import { contextBridge, ipcRenderer } from 'electron';
import type { SovereignKernelBridge } from '../shared/types';

const bridge: SovereignKernelBridge = {
  fs: {
    readFile: (name: string) => ipcRenderer.invoke('fs:read', name),
    writeFile: (name: string, data: string) => ipcRenderer.invoke('fs:write', name, data),
  },
  crypto: {
    regenerateFixture: () => ipcRenderer.invoke('crypto:regenerate'),
    getStatus: () => ipcRenderer.invoke('crypto:status'),
  },
  devices: {
    listSerial: () => ipcRenderer.invoke('devices:list'),
    openSerial: (path: string, baudRate: number) => ipcRenderer.invoke('devices:open', path, baudRate),
    closeSerial: (token: string) => ipcRenderer.invoke('devices:close', token),
  },
  ui: {
    confirmAction: (title: string, message: string) => ipcRenderer.invoke('ui:confirm', title, message),
    showNotification: (title: string, body: string) => ipcRenderer.invoke('ui:notification', title, body),
  },
  ci: {
    runDebug: () => ipcRenderer.invoke('ci:debug'),
  },
  vault: {
    status: () => ipcRenderer.invoke('vault:status'),
    unlock: (provider: string) => ipcRenderer.invoke('vault:unlock', provider),
    lock: () => ipcRenderer.invoke('vault:lock'),
  },
};

contextBridge.exposeInMainWorld('sk', bridge);
