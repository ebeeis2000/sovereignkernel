export interface ApiResult<T = void> {
  ok: boolean;
  data?: T;
  error?: string;
}

export interface SerialPortInfo {
  path: string;
  manufacturer?: string;
  serialNumber?: string;
  vendorId?: string;
  productId?: string;
}

export interface SovereignKernelBridge {
  fs: {
    readFile(name: string): Promise<ApiResult<string>>;
    writeFile(name: string, data: string): Promise<ApiResult>;
  };
  crypto: {
    regenerateFixture(): Promise<ApiResult<string> & { output: string }>;
    getStatus(): Promise<ApiResult<{ tpm: string; chain: string }>>;
  };
  devices: {
    listSerial(): Promise<ApiResult & { ports: readonly SerialPortInfo[] }>;
    openSerial(path: string, baudRate: number): Promise<ApiResult & { token?: string }>;
    closeSerial(token: string): Promise<ApiResult>;
  };
  ui: {
    confirmAction(title: string, message: string): Promise<{ proceed: boolean }>;
    showNotification(title: string, body: string): Promise<void>;
  };
  ci: {
    runDebug(): Promise<ApiResult & { pid?: number }>;
  };
  vault: {
    status(): Promise<ApiResult<{ locked: boolean; tpm: boolean; uptime: number }>>;
    unlock(provider: string): Promise<ApiResult>;
    lock(): Promise<ApiResult>;
  };
}

declare global {
  interface Window {
    sk: SovereignKernelBridge;
  }
}
