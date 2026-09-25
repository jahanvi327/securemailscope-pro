import { useState } from 'react';
import type { SecurityPolicy, TlsVersion } from '@/types';
import { defaultPolicy, clonePolicy } from '@/engine/securityPolicy';
import { Shield, Lock, Key, BadgeCheck, Save, RotateCcw } from 'lucide-react';

interface SettingsPageProps {
  policy: SecurityPolicy;
  onPolicyChange: (policy: SecurityPolicy) => void;
}

export function SettingsPage({ policy, onPolicyChange }: SettingsPageProps) {
  const [local, setLocal] = useState<SecurityPolicy>(clonePolicy(policy));
  const [saved, setSaved] = useState(false);

  const update = (patch: Partial<SecurityPolicy>) => {
    setLocal({ ...local, ...patch });
    setSaved(false);
  };

  const updateWeight = (key: keyof SecurityPolicy['scoreWeights'], value: number) => {
    setLocal({ ...local, scoreWeights: { ...local.scoreWeights, [key]: value } });
    setSaved(false);
  };

  const handleSave = () => {
    onPolicyChange(clonePolicy(local));
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = () => {
    setLocal(clonePolicy(defaultPolicy));
    setSaved(false);
  };

  const toggleDeprecated = (version: TlsVersion) => {
    const versions = local.deprecatedTlsVersions.includes(version)
      ? local.deprecatedTlsVersions.filter(v => v !== version)
      : [...local.deprecatedTlsVersions, version];
    update({ deprecatedTlsVersions: versions });
  };

  const totalWeight = Object.values(local.scoreWeights).reduce((a, b) => a + b, 0);

  return (
    <div className="max-w-3xl mx-auto animate-fade-in space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-100">Settings & Security Policy</h2>
          <p className="text-sm text-slate-500 mt-1">Configure the security policy used for analysis</p>
        </div>
        <div className="flex gap-2">
          <button onClick={handleReset} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 text-sm hover:bg-slate-700 transition-colors">
            <RotateCcw className="w-4 h-4" /> Reset
          </button>
          <button onClick={handleSave} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400 text-sm font-medium hover:bg-sky-500/20 transition-colors">
            <Save className="w-4 h-4" /> {saved ? 'Saved!' : 'Save Policy'}
          </button>
        </div>
      </div>

      {/* TLS versions */}
      <div className="soc-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Lock className="w-5 h-5 text-sky-400" />
          <h3 className="text-sm font-semibold text-slate-200">Deprecated TLS Versions</h3>
        </div>
        <p className="text-sm text-slate-500 mb-4">Select which TLS versions should be flagged as deprecated in security findings.</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {(['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'] as TlsVersion[]).map(v => (
            <label key={v} className="flex items-center gap-2 p-3 rounded-lg bg-slate-800/50 border border-slate-700/50 cursor-pointer hover:border-slate-600 transition-colors">
              <input
                type="checkbox"
                checked={local.deprecatedTlsVersions.includes(v)}
                onChange={() => toggleDeprecated(v)}
                className="rounded border-slate-600 bg-slate-800 text-sky-500 focus:ring-sky-500"
              />
              <span className="text-sm text-slate-300">{v}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Key requirements */}
      <div className="soc-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Key className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-semibold text-slate-200">Key Requirements</h3>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-slate-500 uppercase tracking-wide">Min RSA Key Size (bits)</label>
            <input type="number" value={local.minRsaKeySize} onChange={e => update({ minRsaKeySize: Number(e.target.value) })} className="soc-input w-full mt-1" min={512} max={8192} step={512} />
          </div>
          <div>
            <label className="text-xs text-slate-500 uppercase tracking-wide">Min ECC Key Size (bits)</label>
            <input type="number" value={local.minEccKeySize} onChange={e => update({ minEccKeySize: Number(e.target.value) })} className="soc-input w-full mt-1" min={128} max={521} step={32} />
          </div>
        </div>
      </div>

      {/* Certificate requirements */}
      <div className="soc-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <BadgeCheck className="w-5 h-5 text-emerald-400" />
          <h3 className="text-sm font-semibold text-slate-200">Certificate Requirements</h3>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-slate-500 uppercase tracking-wide">Max Certificate Validity (days)</label>
            <input type="number" value={local.maxCertValidityDays} onChange={e => update({ maxCertValidityDays: Number(e.target.value) })} className="soc-input w-full mt-1" min={30} max={3650} />
          </div>
          <div>
            <label className="text-xs text-slate-500 uppercase tracking-wide">Weak Signature Algorithms (comma-separated)</label>
            <input type="text" value={local.weakSignatureAlgorithms.join(', ')} onChange={e => update({ weakSignatureAlgorithms: e.target.value.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) })} className="soc-input w-full mt-1" />
          </div>
        </div>
      </div>

      {/* Toggles */}
      <div className="soc-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-5 h-5 text-sky-400" />
          <h3 className="text-sm font-semibold text-slate-200">Security Requirements</h3>
        </div>
        <div className="space-y-3">
          <Toggle label="Require Forward Secrecy" description="Flag cipher suites that do not provide forward secrecy." checked={local.requireForwardSecrecy} onChange={v => update({ requireForwardSecrecy: v })} />
          <Toggle label="Require STARTTLS" description="Flag sessions that do not negotiate STARTTLS." checked={local.requireStartTls} onChange={v => update({ requireStartTls: v })} />
        </div>
      </div>

      {/* Score weights */}
      <div className="soc-card p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-purple-400" />
            <h3 className="text-sm font-semibold text-slate-200">Score Weights</h3>
          </div>
          <span className={`text-xs font-medium ${totalWeight === 100 ? 'text-emerald-400' : 'text-amber-400'}`}>Total: {totalWeight}/100</span>
        </div>
        <p className="text-sm text-slate-500 mb-4">Weights determine how much each factor contributes to the overall security score. Total should equal 100.</p>
        <div className="space-y-3">
          {(Object.keys(local.scoreWeights) as (keyof SecurityPolicy['scoreWeights'])[]).map(key => (
            <div key={key}>
              <div className="flex items-center justify-between mb-1">
                <label className="text-sm text-slate-300 capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</label>
                <span className="text-sm text-sky-400 font-medium">{local.scoreWeights[key]}</span>
              </div>
              <input
                type="range"
                min={0}
                max={50}
                value={local.scoreWeights[key]}
                onChange={e => updateWeight(key, Number(e.target.value))}
                className="w-full accent-sky-500"
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Toggle({ label, description, checked, onChange }: { label: string; description: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/50 border border-slate-700/50 cursor-pointer hover:border-slate-600 transition-colors">
      <button
        type="button"
        onClick={() => onChange(!checked)}
        className={`relative shrink-0 w-10 h-6 rounded-full transition-colors ${checked ? 'bg-sky-500' : 'bg-slate-700'}`}
      >
        <span className={`absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform ${checked ? 'translate-x-4' : ''}`} />
      </button>
      <div>
        <p className="text-sm font-medium text-slate-200">{label}</p>
        <p className="text-xs text-slate-500 mt-0.5">{description}</p>
      </div>
    </label>
  );
}
