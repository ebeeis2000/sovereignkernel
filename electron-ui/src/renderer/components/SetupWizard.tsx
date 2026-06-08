import React, { useState } from 'react';

interface WizardStep {
  title: string;
  description: string;
}

const STEPS: WizardStep[] = [
  { title: 'Welkom', description: 'SovereignKernel Vault beschermt je gevoelige gegevens met hardware-beveiliging.' },
  { title: 'TPM Configuratie', description: 'Controleer of je systeem een TPM 2.0 chip heeft voor maximale beveiliging.' },
  { title: 'Master Key', description: 'Kies hoe je master key wordt beveiligd: TPM, wachtwoord, of Shamir-deling.' },
  { title: 'Backup Instellingen', description: 'Configureer automatische backups om dataverlies te voorkomen.' },
  { title: 'Gereed', description: 'Je vault is geconfigureerd en klaar voor gebruik!' },
];

interface SetupWizardProps {
  onComplete: () => void;
}

export function SetupWizard({ onComplete }: SetupWizardProps): React.ReactElement {
  const [step, setStep] = useState(0);
  const [config, setConfig] = useState({
    protectionMode: 'tpm' as 'tpm' | 'password' | 'shamir',
    autoBackup: true,
    backupInterval: 24,
    autoLockMinutes: 10,
    tpmAvailable: false,
  });

  const handleNext = (): void => {
    if (step < STEPS.length - 1) {
      setStep(step + 1);
    } else {
      onComplete();
    }
  };

  const handleBack = (): void => {
    if (step > 0) setStep(step - 1);
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '600px', margin: '0 auto' }}>
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', gap: '4px', marginBottom: '1rem' }}>
          {STEPS.map((_, i) => (
            <div
              key={i}
              style={{
                flex: 1,
                height: '4px',
                borderRadius: '2px',
                background: i <= step ? '#f59e0b' : '#374151',
              }}
            />
          ))}
        </div>
        <h2 style={{ color: '#f59e0b', margin: '0 0 0.5rem 0' }}>{STEPS[step].title}</h2>
        <p style={{ color: '#9ca3af', margin: 0 }}>{STEPS[step].description}</p>
      </div>

      <div style={{ minHeight: '200px', marginBottom: '2rem' }}>
        {step === 0 && (
          <div>
            <p style={{ color: '#e5e7eb' }}>
              Deze wizard helpt je om SovereignKernel Vault in te richten.
              Je gegevens worden beschermd met:
            </p>
            <ul style={{ color: '#d1d5db', lineHeight: '2' }}>
              <li>AES-256-GCM versleuteling</li>
              <li>Hardware TPM 2.0 binding (indien beschikbaar)</li>
              <li>Shamir secret sharing voor herstel</li>
              <li>Tamper-evident audit logging</li>
            </ul>
          </div>
        )}

        {step === 1 && (
          <div>
            <div style={{
              padding: '1rem',
              borderRadius: '8px',
              background: config.tpmAvailable ? '#064e3b' : '#7c2d12',
              marginBottom: '1rem',
            }}>
              <strong style={{ color: config.tpmAvailable ? '#6ee7b7' : '#fca5a5' }}>
                {config.tpmAvailable ? '✓ TPM 2.0 gevonden' : '⚠ Geen TPM gevonden'}
              </strong>
              <p style={{ color: '#d1d5db', margin: '0.5rem 0 0 0', fontSize: '0.9rem' }}>
                {config.tpmAvailable
                  ? 'Je systeem ondersteunt hardware-beveiligde key opslag.'
                  : 'Software-modus wordt gebruikt. Overweeeg een TPM voor extra beveiliging.'}
              </p>
            </div>
          </div>
        )}

        {step === 2 && (
          <div>
            <label style={{ color: '#e5e7eb', display: 'block', marginBottom: '1rem' }}>
              Beveiligingsmethode:
              <select
                value={config.protectionMode}
                onChange={(e) => setConfig({ ...config, protectionMode: e.target.value as typeof config.protectionMode })}
                style={{
                  display: 'block', width: '100%', padding: '0.5rem',
                  background: '#1f2937', color: '#e5e7eb', border: '1px solid #374151',
                  borderRadius: '4px', marginTop: '0.5rem',
                }}
              >
                <option value="tpm">TPM Hardware Key (aanbevolen)</option>
                <option value="password">Wachtwoord met Argon2id</option>
                <option value="shamir">Shamir Secret Sharing (3-van-5)</option>
              </select>
            </label>

            <label style={{ color: '#e5e7eb', display: 'block', marginBottom: '1rem' }}>
              Auto-lock na inactiviteit (minuten):
              <input
                type="number"
                min={1}
                max={60}
                value={config.autoLockMinutes}
                onChange={(e) => setConfig({ ...config, autoLockMinutes: parseInt(e.target.value) || 10 })}
                style={{
                  display: 'block', width: '100%', padding: '0.5rem',
                  background: '#1f2937', color: '#e5e7eb', border: '1px solid #374151',
                  borderRadius: '4px', marginTop: '0.5rem',
                }}
              />
            </label>
          </div>
        )}

        {step === 3 && (
          <div>
            <label style={{ color: '#e5e7eb', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <input
                type="checkbox"
                checked={config.autoBackup}
                onChange={(e) => setConfig({ ...config, autoBackup: e.target.checked })}
              />
              Automatische backups inschakelen
            </label>

            {config.autoBackup && (
              <label style={{ color: '#e5e7eb', display: 'block', marginBottom: '1rem' }}>
                Backup interval (uren):
                <input
                  type="number"
                  min={1}
                  max={168}
                  value={config.backupInterval}
                  onChange={(e) => setConfig({ ...config, backupInterval: parseInt(e.target.value) || 24 })}
                  style={{
                    display: 'block', width: '100%', padding: '0.5rem',
                    background: '#1f2937', color: '#e5e7eb', border: '1px solid #374151',
                    borderRadius: '4px', marginTop: '0.5rem',
                  }}
                />
              </label>
            )}
          </div>
        )}

        {step === 4 && (
          <div style={{ textAlign: 'center', padding: '2rem 0' }}>
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔒</div>
            <p style={{ color: '#6ee7b7', fontWeight: 'bold', fontSize: '1.2rem' }}>
              Configuratie voltooid!
            </p>
            <p style={{ color: '#9ca3af' }}>
              Je vault is beveiligd met {config.protectionMode === 'tpm' ? 'TPM hardware' :
                config.protectionMode === 'password' ? 'Argon2id wachtwoord' : 'Shamir sharing'}.
            </p>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <button
          onClick={handleBack}
          disabled={step === 0}
          style={{
            padding: '0.5rem 1.5rem', borderRadius: '4px',
            background: step === 0 ? '#374151' : '#4b5563',
            color: step === 0 ? '#6b7280' : '#e5e7eb',
            border: 'none', cursor: step === 0 ? 'not-allowed' : 'pointer',
          }}
        >
          Vorige
        </button>
        <button
          onClick={handleNext}
          style={{
            padding: '0.5rem 1.5rem', borderRadius: '4px',
            background: '#f59e0b', color: '#000', border: 'none',
            cursor: 'pointer', fontWeight: 'bold',
          }}
        >
          {step === STEPS.length - 1 ? 'Voltooien' : 'Volgende'}
        </button>
      </div>
    </div>
  );
}
