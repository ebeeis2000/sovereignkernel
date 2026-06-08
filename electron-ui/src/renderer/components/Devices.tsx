import React, { useEffect, useState, type FC } from 'react';
import type { SerialPortInfo, SovereignKernelBridge } from '../../shared/types';

function getBridge(): SovereignKernelBridge { return window.sk; }

export const Devices: FC = () => {
  const [ports, setPorts] = useState<readonly SerialPortInfo[]>([]);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    setLoading(true);
    const r = await getBridge().devices.listSerial();
    setLoading(false);
    if (r.ok) setPorts(r.ports);
  };

  useEffect(() => { refresh(); }, []);

  return (
    <div style={{ background: '#fff', padding: 24, borderRadius: 8, boxShadow: '0 1px 3px rgba(0,0,0,.08)', maxWidth: 800 }}>
      <h2 style={{ marginTop: 0 }}>USB / Serial Interfaces</h2>
      <button
        style={{ padding: '10px 20px', background: '#0f172a', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', marginBottom: 16 }}
        onClick={refresh}
        disabled={loading}
      >
        {loading ? 'Scanning...' : 'Scan Devices'}
      </button>
      {ports.length === 0 && <p>No devices detected.</p>}
      <ul style={{ listStyle: 'none', padding: 0 }}>
        {ports.map(p => (
          <li key={p.path} style={{ padding: 16, border: '1px solid #e2e8f0', borderRadius: 6, marginBottom: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <strong style={{ fontFamily: 'monospace' }}>{p.path}</strong><br/>
              <span style={{ fontSize: '0.8rem', color: '#64748b' }}>{p.manufacturer ?? 'Unknown'}</span>
            </div>
            <button
              style={{ padding: '8px 16px', background: '#16a34a', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
              onClick={async () => {
                const r = await getBridge().devices.openSerial(p.path, 115200);
                alert(r.ok ? `Token: ${r.token}` : r.error);
              }}
            >
              Connect
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
};
