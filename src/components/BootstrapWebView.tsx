import React, { useState, useEffect } from 'react';
import { storageEngine } from '../services/storageSimulator';
import { ScanResult, CleanupLog, OsintThreatCheckResponse } from '../types';
import { playSound } from '../utils/audio';
import { MaliciousWarningModal } from './MaliciousWarningModal';
import { 
  HardDrive, 
  Clock, 
  Search, 
  Trash2, 
  CheckCircle, 
  Layers, 
  X,
  FileCode,
  Terminal,
  ShieldAlert
} from 'lucide-react';

interface BootstrapWebViewProps {
  onOpenOsintModal?: () => void;
  onRefreshParent?: () => void;
}

export const BootstrapWebView: React.FC<BootstrapWebViewProps> = ({ onOpenOsintModal, onRefreshParent }) => {
  const [scanData, setScanData] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatusText, setScanStatusText] = useState('Ready to perform full analysis');
  const [displaySizeText, setDisplaySizeText] = useState('0 MB');
  const [cleanedCategories, setCleanedCategories] = useState<Record<string, boolean>>({});
  const [cleaningCategories, setCleaningCategories] = useState<Record<string, boolean>>({});
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [historyLogs, setHistoryLogs] = useState<CleanupLog[]>([]);
  const [lastApiCall, setLastApiCall] = useState<{ method: string; endpoint: string; payload?: unknown; response?: unknown } | null>(null);
  const [showNetworkInspector, setShowNetworkInspector] = useState(false);
  
  // OSINT threat confirmation state
  const [pendingThreat, setPendingThreat] = useState<{
    threat: OsintThreatCheckResponse;
    categoryName: string;
    bytes: number;
    files: number;
  } | null>(null);

  useEffect(() => {
    setHistoryLogs(storageEngine.getLogs());
  }, []);

  const handleRunScan = async () => {
    setIsScanning(true);
    setDisplaySizeText('Scanning...');
    playSound('scan');

    setLastApiCall({
      method: 'GET',
      endpoint: 'api.php?action=scan',
      response: 'Waiting for response...',
    });

    const result = await storageEngine.runScan((stage) => {
      setScanStatusText(stage);
    });

    setScanData(result);
    setIsScanning(false);
    const megabytes = (result.total_bytes / (1024 * 1024)).toFixed(1);
    setDisplaySizeText(`${megabytes} MB`);
    setScanStatusText(`${result.total_files} junk items found`);
    setCleanedCategories({});
    playSound('beep');

    setLastApiCall({
      method: 'GET',
      endpoint: 'api.php?action=scan',
      response: {
        status: 'success',
        total_files: result.total_files,
        total_bytes: result.total_bytes,
        categories: Object.fromEntries(
          Object.entries(result.categories).map(([k, v]) => [k, { count: v.count, size: v.size }])
        )
      }
    });

    if (onRefreshParent) onRefreshParent();
  };

  const handleCleanCategory = async (categoryName: string, bytes: number, files: number, forceConfirm = false) => {
    setCleaningCategories(prev => ({ ...prev, [categoryName]: true }));
    playSound('clean');

    const requestBody = { 
      category: categoryName, 
      bytes_freed: bytes, 
      files_removed: files,
      force_confirm: forceConfirm
    };

    setLastApiCall({
      method: 'POST',
      endpoint: 'api.php?action=clean',
      payload: requestBody,
      response: 'Running VirusTotal OSINT heuristic check...'
    });

    // Simulate API delay
    await new Promise(r => setTimeout(r, 500));

    const cleanResult = await storageEngine.cleanCategory(categoryName, forceConfirm);

    // If malicious file flagged and requires user confirmation
    if (cleanResult.status === 'warning' && cleanResult.requires_confirmation && cleanResult.threat_info) {
      playSound('alert');
      setCleaningCategories(prev => ({ ...prev, [categoryName]: false }));
      setPendingThreat({
        threat: cleanResult.threat_info,
        categoryName,
        bytes,
        files
      });

      setLastApiCall({
        method: 'POST',
        endpoint: 'api.php?action=clean',
        payload: requestBody,
        response: {
          status: 'warning',
          requires_confirmation: true,
          threat_info: cleanResult.threat_info,
          message: cleanResult.message
        }
      });
      return;
    }

    setCleaningCategories(prev => ({ ...prev, [categoryName]: false }));
    setCleanedCategories(prev => ({ ...prev, [categoryName]: true }));
    playSound('success');

    // Update remaining size
    if (scanData && scanData.categories[categoryName]) {
      const remainingBytes = Math.max(0, scanData.total_bytes - bytes);
      const remainingFiles = Math.max(0, scanData.total_files - files);
      scanData.total_bytes = remainingBytes;
      scanData.total_files = remainingFiles;
      setDisplaySizeText(`${(remainingBytes / (1024 * 1024)).toFixed(1)} MB`);
      setScanStatusText(`${remainingFiles} junk items remaining`);
    }

    setLastApiCall({
      method: 'POST',
      endpoint: 'api.php?action=clean',
      payload: requestBody,
      response: {
        status: 'success',
        message: `Successfully cleaned ${categoryName}`,
        bytes_freed: bytes
      }
    });

    setHistoryLogs(storageEngine.getLogs());
    if (onRefreshParent) onRefreshParent();
  };

  const handleConfirmMaliciousDelete = async () => {
    if (!pendingThreat) return;
    const { categoryName, bytes, files } = pendingThreat;
    setPendingThreat(null);
    await handleCleanCategory(categoryName, bytes, files, true);
  };

  const handleOpenHistory = () => {
    playSound('beep');
    setHistoryLogs(storageEngine.getLogs());
    setShowHistoryModal(true);
    setLastApiCall({
      method: 'GET',
      endpoint: 'api.php?action=history',
      response: {
        status: 'success',
        history: storageEngine.getLogs().slice(0, 10)
      }
    });
  };

  return (
    <div className="min-h-full bg-slate-900 text-slate-100 flex flex-col font-sans pb-6">
      
      {/* Bootstrap Top App Bar */}
      <div className="px-4 py-3 bg-slate-900 border-b border-slate-700/80 flex items-center justify-between sticky top-0 z-20">
        <div className="flex items-center gap-2">
          <HardDrive className="w-5 h-5 text-cyan-400" />
          <span className="font-bold text-base tracking-tight text-cyan-400">Storage Cleaner</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono">
            PHP+SQLite
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button 
            type="button" 
            onClick={() => setShowNetworkInspector(!showNetworkInspector)}
            title="Inspect REST API Calls"
            className="p-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <Terminal className="w-4 h-4 text-emerald-400" />
          </button>
          <button 
            type="button" 
            onClick={handleOpenHistory}
            title="Cleanup History"
            className="p-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <Clock className="w-4 h-4 text-cyan-300" />
          </button>
        </div>
      </div>

      {/* Network API Request/Response Inspector Drawer */}
      {showNetworkInspector && (
        <div className="mx-3 mt-3 p-3 rounded-xl bg-slate-950 border border-slate-700/80 text-xs font-mono">
          <div className="flex items-center justify-between pb-1 border-b border-slate-800 mb-2">
            <span className="text-emerald-400 font-bold flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5" />
              REST API Traffic: api.php
            </span>
            <button onClick={() => setShowNetworkInspector(false)} className="text-slate-500 hover:text-slate-300">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          {lastApiCall ? (
            <div className="space-y-1.5">
              <div className="flex gap-2">
                <span className="px-1 py-0.5 rounded bg-blue-900/60 text-blue-300 font-bold">{lastApiCall.method}</span>
                <span className="text-slate-300">{lastApiCall.endpoint}</span>
              </div>
              {lastApiCall.payload != null && (
                <div className="text-slate-400">
                  <span className="text-slate-500">Payload: </span>
                  {JSON.stringify(lastApiCall.payload)}
                </div>
              )}
              <div className="text-emerald-300 truncate max-h-16 overflow-hidden">
                <span className="text-slate-500">Response: </span>
                {JSON.stringify(lastApiCall.response)}
              </div>
            </div>
          ) : (
            <span className="text-slate-500">No API calls recorded yet. Tap Analyze Storage.</span>
          )}
        </div>
      )}

      {/* Container Content */}
      <div className="p-4 flex-1 flex flex-col">
        {/* Main Dashboard Gauge Card */}
        <div className="rounded-2xl p-6 text-center mb-4 bg-gradient-to-br from-slate-800/90 via-slate-800 to-slate-900 border border-slate-700 shadow-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 -mr-8 -mt-8 w-32 h-32 rounded-full bg-cyan-500/10 blur-2xl pointer-events-none" />
          
          <p className="text-slate-400 text-xs uppercase tracking-wider font-semibold mb-1">
            Junk Files Detected
          </p>
          
          <h1 className="text-4xl font-extrabold text-white my-2 tracking-tight">
            {displaySizeText}
          </h1>

          <p className="text-slate-400 text-xs mb-5">
            {scanStatusText}
          </p>

          <button
            type="button"
            disabled={isScanning}
            onClick={handleRunScan}
            className="w-full py-3.5 px-6 rounded-full text-white font-bold text-sm tracking-wide bg-gradient-to-r from-sky-500 via-blue-600 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 active:scale-[0.98] transition-all duration-150 shadow-lg shadow-blue-600/30 flex items-center justify-center gap-2 disabled:opacity-60 cursor-pointer"
          >
            <Search className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            {isScanning ? 'ANALYZING STORAGE...' : 'ANALYZE STORAGE'}
          </button>
        </div>

        {/* Detected Categories List */}
        <div className="flex items-center justify-between mb-3 px-1">
          <h6 className="text-[11px] uppercase tracking-wider text-slate-400 font-bold">
            Cleanup Modules
          </h6>
          {scanData && (
            <span className="text-[11px] text-cyan-400 font-mono">
              {Object.keys(scanData.categories).length} modules ready
            </span>
          )}
        </div>

        <div className="space-y-2.5 flex-1">
          {!scanData ? (
            <div className="text-center py-10 px-4 rounded-xl border border-dashed border-slate-800 bg-slate-900/50">
              <Layers className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              <p className="text-slate-400 text-xs font-medium">Tap "Analyze Storage" to run local diagnostic.</p>
              <p className="text-slate-500 text-[11px] mt-1">Queries app cache, temp directories & media thumbnails</p>
            </div>
          ) : (
            Object.entries(scanData.categories).map(([cat, info]) => {
              const catMB = (info.size / (1024 * 1024)).toFixed(1);
              const isCleaned = cleanedCategories[cat];
              const isCleaning = cleaningCategories[cat];

              return (
                <div
                  key={cat}
                  className="p-3.5 rounded-xl bg-slate-800/80 border border-slate-700/80 flex items-center justify-between shadow-sm hover:border-slate-600 transition-colors"
                >
                  <div className="pr-3">
                    <div className="font-semibold text-slate-100 text-sm flex items-center gap-1.5">
                      {cat}
                      {cat === 'Orphaned APKs' && (
                        <span className="text-[9px] px-1 py-0.2 rounded bg-amber-950 border border-amber-800 text-amber-300 font-mono">
                          OSINT Threat
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      {isCleaned ? '0 files (0.0 MB)' : `${info.count} files (${catMB} MB)`}
                    </div>
                  </div>

                  <div>
                    {isCleaned ? (
                      <span className="inline-flex items-center gap-1 text-xs font-semibold px-3 py-1.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800/80">
                        <CheckCircle className="w-3.5 h-3.5" />
                        Done
                      </span>
                    ) : (
                      <button
                        type="button"
                        disabled={isCleaning || info.count === 0}
                        onClick={() => handleCleanCategory(cat, info.size, info.count)}
                        className="text-xs font-semibold px-4 py-1.5 rounded-full border border-cyan-500 text-cyan-300 hover:bg-cyan-500 hover:text-white transition-all disabled:opacity-40 cursor-pointer"
                      >
                        {isCleaning ? 'Cleaning...' : 'Clean'}
                      </button>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Bootstrap History Modal Replica */}
      {showHistoryModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-sm overflow-hidden shadow-2xl flex flex-col max-h-[85vh]">
            <div className="px-4 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <h5 className="text-sm font-bold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                Cleanup History (SQLite)
              </h5>
              <button
                type="button"
                onClick={() => setShowHistoryModal(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto flex-1 divide-y divide-slate-800">
              {historyLogs.length === 0 ? (
                <div className="text-center py-8 text-slate-500 text-xs">
                  No cleanup logs in SQLite database.
                </div>
              ) : (
                historyLogs.map(item => {
                  const mb = (item.bytes_freed / (1024 * 1024)).toFixed(1);
                  return (
                    <div key={item.id} className="py-2.5 flex items-center justify-between first:pt-0 last:pb-0">
                      <div>
                        <div className="font-semibold text-slate-200 text-xs">{item.category}</div>
                        <div className="text-[10px] text-slate-400 mt-0.5">{item.cleaned_at}</div>
                      </div>
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-blue-900/60 text-blue-300 border border-blue-700/60 font-semibold">
                        {mb} MB Freed
                      </span>
                    </div>
                  );
                })
              )}
            </div>

            <div className="px-4 py-3 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-[11px] text-slate-400">
              <span>Table: <code className="text-cyan-300">cleanup_logs</code></span>
              <button
                type="button"
                onClick={() => setShowHistoryModal(false)}
                className="px-3 py-1 rounded-md bg-slate-800 text-slate-200 hover:bg-slate-700 font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* OSINT Malicious File Warning Modal */}
      {pendingThreat && (
        <MaliciousWarningModal
          threat={pendingThreat.threat}
          onConfirmDelete={handleConfirmMaliciousDelete}
          onCancel={() => {
            setPendingThreat(null);
            playSound('pop');
          }}
        />
      )}

    </div>
  );
};
