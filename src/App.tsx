import { useState, useEffect } from 'react';
import type { AnalysisResult, SecurityPolicy } from '@/types';
import { Sidebar, type PageId } from '@/components/Sidebar';
import { Dashboard } from '@/pages/Dashboard';
import { UploadPage } from '@/pages/UploadPage';
import { SessionsPage } from '@/pages/SessionsPage';
import { FindingsPage } from '@/pages/FindingsPage';
import { CertificatesPage } from '@/pages/CertificatesPage';
import { TlsPage } from '@/pages/TlsPage';
import { ReportsPage } from '@/pages/ReportsPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { defaultPolicy } from '@/engine/securityPolicy';
import { Shield } from 'lucide-react';

function App() {
  const [currentPage, setCurrentPage] = useState<PageId>('dashboard');
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [policy, setPolicy] = useState<SecurityPolicy>(defaultPolicy);

  const hasAnalysis = analysis !== null;

  const handleNavigate = (page: string) => {
    setCurrentPage(page as PageId);
  };

  const handleAnalysisComplete = (result: AnalysisResult) => {
    setAnalysis(result);
  };

  const handlePolicyChange = (newPolicy: SecurityPolicy) => {
    setPolicy(newPolicy);
  };

  // Scroll to top on page change
  useEffect(() => {
    const main = document.getElementById('main-content');
    if (main) main.scrollTo(0, 0);
  }, [currentPage]);

  return (
    <div className="min-h-screen bg-slate-950 flex">
      <Sidebar currentPage={currentPage} onNavigate={handleNavigate} hasAnalysis={hasAnalysis} />

      <main id="main-content" className="app-main min-w-0 flex-1 overflow-y-auto scrollbar-thin min-h-screen">
        <div className="grid-pattern min-h-full">
          <div className="app-content max-w-7xl mx-auto px-6 py-8">
            {!hasAnalysis && currentPage !== 'upload' && currentPage !== 'settings' && (
              <div className="empty-state flex flex-col items-center justify-center min-h-[60vh] text-center">
                <div className="diagnostic-orbit w-24 h-24 rounded-full flex items-center justify-center mb-6">
                  <Shield className="w-8 h-8 text-sky-400" />
                </div>
                <h2 className="text-xl font-bold text-slate-200 mb-2">No Analysis Data</h2>
                <p className="text-sm text-slate-500 mb-6 max-w-md">Upload a PCAP file or load the demo dataset to start analyzing email security posture.</p>
                <button
                  onClick={() => setCurrentPage('upload')}
                  className="px-5 py-2.5 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400 text-sm font-medium hover:bg-sky-500/20 transition-colors"
                >
                  Go to Upload
                </button>
              </div>
            )}

            {analysis && currentPage === 'dashboard' && <Dashboard result={analysis} />}
            {currentPage === 'upload' && <UploadPage onAnalysisComplete={handleAnalysisComplete} onNavigate={handleNavigate} />}
            {analysis && currentPage === 'sessions' && <SessionsPage result={analysis} />}
            {analysis && currentPage === 'findings' && <FindingsPage result={analysis} />}
            {analysis && currentPage === 'certificates' && <CertificatesPage result={analysis} />}
            {analysis && currentPage === 'tls' && <TlsPage result={analysis} />}
            {analysis && currentPage === 'reports' && <ReportsPage result={analysis} />}
            {currentPage === 'settings' && <SettingsPage policy={policy} onPolicyChange={handlePolicyChange} />}
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
