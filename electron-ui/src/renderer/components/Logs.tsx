import React, { useState, type FC } from 'react';
import type { SovereignKernelBridge } from '../../shared/types';

function getBridge(): SovereignKernelBridge { return window.sk; }

export const Logs: FC = () => {
  const [log, setLog] = useState('Audit logs require authorization.');

  return (
    <div style={{ background: '#fff', padding: 24, borderRadius: 8, boxShadow: '0 1px 3px rgba(0,0,0,.08)', maxWidth: 800 }}>
      <h2 style={{ marginTop: 0 }}>Logs & Audit Trail</h2>
      <button
        style={{ padding: '10px 20px', background: '#475569', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', marginBottom: 16 }}
        onClick={async () => {
          const r = await getBridge().fs.readFile('audit_trail.log');
          setLog(r.ok ? (r.data || 'Empty') : (r.error ?? 'Access denied'));
        }}
      >
        Read Local Audit Container
      </button>
      <pre style={{ background: '#1e293b', color: '#e2e8f0', padding: 20, borderRadius: 6, overflowX: 'auto', whiteSpace: 'pre-wrap', fontFamily: 'monospace', minHeight: 200, maxHeight: 500, overflowY: 'auto' }}>
        {log}
      </pre>
    </div>
  );
};
