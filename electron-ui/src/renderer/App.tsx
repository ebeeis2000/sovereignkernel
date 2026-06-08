import React, { useState, type FC, type PropsWithChildren, type ErrorInfo } from 'react';

const Dashboard = React.lazy(() => import('./components/Dashboard').then(m => ({ default: m.Dashboard })));
const Devices = React.lazy(() => import('./components/Devices').then(m => ({ default: m.Devices })));
const CryptoConsole = React.lazy(() => import('./components/CryptoConsole').then(m => ({ default: m.CryptoConsole })));
const Logs = React.lazy(() => import('./components/Logs').then(m => ({ default: m.Logs })));

interface TabDef { id: string; label: string; component: React.LazyExoticComponent<FC> }

const TABS: TabDef[] = [
  { id: 'dashboard', label: 'Dashboard', component: Dashboard },
  { id: 'devices', label: 'Devices', component: Devices },
  { id: 'crypto', label: 'Crypto Console', component: CryptoConsole },
  { id: 'logs', label: 'Logs & Audit', component: Logs },
];

class ErrorBoundary extends React.Component<PropsWithChildren, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('[ErrorBoundary]', error, info); }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 40, color: '#dc2626' }}>
          <h2>Er is een fout opgetreden</h2>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{this.state.error.message}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

export const App: FC = () => {
  const [tab, setTab] = useState('dashboard');
  const ActiveTab = TABS.find(t => t.id === tab)?.component ?? Dashboard;

  return (
    <div style={{ display: 'flex', height: '100vh', fontFamily: 'Segoe UI, sans-serif', backgroundColor: '#f1f5f9' }}>
      <aside style={{ width: 260, backgroundColor: '#0f172a', color: '#e2e8f0', padding: '24px 16px', display: 'flex', flexDirection: 'column' }}>
        <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#38bdf8', marginBottom: 32 }}>SovereignKernel</h1>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '12px 16px',
                textAlign: 'left',
                backgroundColor: tab === t.id ? '#1e293b' : 'transparent',
                color: tab === t.id ? '#f8fafc' : '#cbd5e1',
                border: 'none',
                borderRadius: 6,
                cursor: 'pointer',
                fontSize: '0.9rem',
                fontWeight: 500,
              }}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </aside>
      <main style={{ flex: 1, padding: 32, overflowY: 'auto' }}>
        <ErrorBoundary>
          <React.Suspense fallback={<div style={{ padding: 40, textAlign: 'center' }}>Laden...</div>}>
            <ActiveTab />
          </React.Suspense>
        </ErrorBoundary>
      </main>
    </div>
  );
};
