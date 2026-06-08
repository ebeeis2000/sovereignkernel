import React, { useState, type FC } from 'react';
import type { SovereignKernelBridge } from '../../shared/types';

function getBridge(): SovereignKernelBridge { return window.sk; }

export const CryptoConsole: FC = () => {
  const [out, setOut] = useState('Console ready.');

  return (
    <div style={{ background: '#fff', padding: 24, borderRadius: 8, boxShadow: '0 1px 3px rgba(0,0,0,.08)', maxWidth: 800 }}>
      <h2 style={{ marginTop: 0 }}>Crypto Console</h2>
      <button
        style={{ padding: '10px 20px', background: '#dc2626', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', marginBottom: 16 }}
        onClick={async () => {
          const c = await getBridge().ui.confirmAction('Regenerate', 'Overwrite vectors?');
          if (!c.proceed) return;
          setOut('Running...');
          const r = await getBridge().crypto.regenerateFixture();
          setOut(r.ok ? r.output : (r.error ?? 'Unknown error'));
        }}
      >
        Regenerate Matrix
      </button>
      <pre style={{ background: '#0f172a', color: '#38bdf8', padding: 20, borderRadius: 6, overflowX: 'auto', whiteSpace: 'pre-wrap', fontFamily: 'monospace', minHeight: 120 }}>
        {out}
      </pre>
    </div>
  );
};
