import { useState, useCallback } from 'react';
import type { AnalysisResult } from '@/types';
import { validateFile, analyzePcapFile, loadDemoAnalysis } from '@/engine/analyzer';
import { Upload, FileUp, ShieldCheck, AlertCircle, Loader2, FlaskConical, Lock } from 'lucide-react';

interface UploadPageProps {
  onAnalysisComplete: (result: AnalysisResult) => void;
  onNavigate: (page: string) => void;
}

export function UploadPage({ onAnalysisComplete, onNavigate }: UploadPageProps) {
  const [dragActive, setDragActive] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string>('');

  const handleFile = useCallback(async (file: File) => {
    setError(null);
    const validation = validateFile(file);
    if (!validation.valid) {
      setError(validation.error || 'Invalid file.');
      return;
    }

    setAnalyzing(true);
    setProgress('Reading file...');

    try {
      const buffer = await file.arrayBuffer();
      setProgress('Validating PCAP format...');
      await sleep(200);

      setProgress('Parsing packets and extracting TCP streams...');
      await sleep(300);

      setProgress('Detecting email protocols (SMTP, IMAP, POP3)...');
      await sleep(200);

      const result = analyzePcapFile(buffer, file.name, file.size);
      setProgress('Analyzing TLS and certificates...');
      await sleep(300);

      setProgress('Applying AI-assisted risk prioritization...');
      await sleep(200);

      onAnalysisComplete(result);
      onNavigate('dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred during analysis.');
    } finally {
      setAnalyzing(false);
      setProgress('');
    }
  }, [onAnalysisComplete, onNavigate]);

  const handleDemo = useCallback(() => {
    setAnalyzing(true);
    setProgress('Loading synthetic demo dataset...');
    setTimeout(() => {
      const result = loadDemoAnalysis();
      onAnalysisComplete(result);
      onNavigate('dashboard');
      setAnalyzing(false);
      setProgress('');
    }, 800);
  }, [onAnalysisComplete, onNavigate]);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  return (
    <div className="max-w-3xl mx-auto animate-fade-in">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-slate-100">Upload PCAP File</h2>
        <p className="text-sm text-slate-500 mt-1">Upload a network capture file to analyze email security posture</p>
      </div>

      {/* Security notice */}
      <div className="soc-card p-4 mb-6 flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
        <div className="text-sm text-slate-400">
          <p className="text-slate-300 font-medium">Defensive Analysis Only</p>
          <p className="mt-1">SecureMailScope performs passive analysis of your PCAP files. It does not perform active attacks, exploitation, or interception. Files are processed locally in your browser and never uploaded to a server.</p>
        </div>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
        onDragLeave={() => setDragActive(false)}
        onDrop={onDrop}
        className={`relative border-2 border-dashed rounded-xl p-6 sm:p-12 text-center transition-all ${
          dragActive ? 'border-sky-500 bg-sky-500/5' : 'border-slate-700 bg-slate-900/50'
        }`}
      >
        <input
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={analyzing}
        />

        {analyzing ? (
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="w-12 h-12 text-sky-400 animate-spin" />
            <p className="text-slate-300 font-medium">{progress}</p>
            <div className="w-full max-w-64 h-1 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-sky-500 animate-pulse-glow" style={{ width: '70%' }} />
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-sky-500/20 to-cyan-500/20 flex items-center justify-center">
              <FileUp className="w-8 h-8 text-sky-400" />
            </div>
            <div>
              <p className="text-lg font-medium text-slate-200">Drop PCAP file here or click to browse</p>
              <p className="text-sm text-slate-500 mt-1">Supports .pcap, .pcapng, .cap — max 50 MB</p>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="mt-4 p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-400">Upload Error</p>
            <p className="text-sm text-slate-400 mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Demo button */}
      <div className="mt-6 soc-card p-6">
        <div className="flex items-center gap-3 mb-3">
          <FlaskConical className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-semibold text-slate-200">Demo Mode</h3>
        </div>
        <p className="text-sm text-slate-400 mb-4">
          No PCAP file available? Load a synthetic demo dataset containing examples of TLS 1.3, TLS 1.2, deprecated TLS, expired certificates, weak certificates, STARTTLS sessions, and plaintext sessions.
        </p>
        <button
          onClick={handleDemo}
          disabled={analyzing}
          className="px-4 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 text-sm font-medium hover:bg-amber-500/20 transition-colors disabled:opacity-50"
        >
          Load Demo Dataset
        </button>
      </div>

      {/* What gets analyzed */}
      <div className="mt-6 soc-card p-6">
        <h3 className="text-sm font-semibold text-slate-200 mb-4">What Gets Analyzed</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            { icon: Upload, text: 'PCAP/PCAPNG file validation' },
            { icon: Lock, text: 'TLS version and cipher suite analysis' },
            { icon: ShieldCheck, text: 'X.509 certificate inspection' },
            { icon: AlertCircle, text: 'STARTTLS negotiation detection' },
          ].map((item, i) => (
            <div key={i} className="flex items-center gap-3 text-sm text-slate-400">
              <item.icon className="w-4 h-4 text-sky-400 shrink-0" />
              {item.text}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
