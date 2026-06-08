import React, { useEffect, useState, type FC } from 'react';
import type { SovereignKernelBridge } from '../../shared/types';

function getBridge(): SovereignKernelBridge { return window.sk; }

export const Dashboard: FC = () => {
  const [tpm, setTpm] = useState('Initializing...');
  const [fixture, setFixture] = useState('Checking...');

  useEffect(() => {
    (async () => {
      try {
        const status = await getBridge().vault.status();
        if (status.ok && status.data) {
          setTpm(status.data.tpm ? 'Operational (Hardware Attested)' : 'Software Mode');
        }
        const r = await getBridge().fs.readFile('interop_fixtures.json');
        setFixture(r.ok && r.data ? 'Active & Validated' : 'No telemetry');
      } catch {
        setTpm('Unavailable');
        setFixture('Error');
      }
    })();
  }, []);

  return (
    <div style={{ background: '#fff', padding: 24, borderRadius: 8, boxShadow: '0 1px 3px rgba(0,0,0,.08)', maxWidth: 800 }}>
      <h2 style={{ marginTop: 0, borderBottom: '1px solid #e2e8f0', paddingBottom: 12 }}>System Dashboard</h2>
      <section style={{ marginBottom: 24 }}>
        <h3>TPM Status</h3>
        <p>Telemetry: <strong style={{ color: '#16a34a' }}>{tpm}</strong></p>
        <button
          style={{ padding: '10px 20px', background: '#0284c7', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}
          onClick={async () => {
            const c = await getBridge().ui.confirmAction('Run Diagnostic', 'Scan interfaces?');
            if (c.proceed) {
              const r = await getBridge().ci.runDebug();
              alert(r.ok ? `PID: ${r.pid}` : r.error);
            }
          }}
        >
          Run Diagnostic
        </button>
      </section>
      <section>
        <h3>Interop Fixtures</h3>
        <p>Status: <strong>{fixture}</strong></p>
      </section>
    </div>
  );
};
