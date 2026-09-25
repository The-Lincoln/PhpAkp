import React, { useState, useEffect } from 'react';
import { storageEngine } from '../services/storageSimulator';
import { ScanResult, CategorySummary, JunkFile, OsintThreatCheckResponse } from '../types';
import { playSound } from '../utils/audio';
import { MaliciousWarningModal } from './MaliciousWarningModal';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Trash2, 
  Search, 
  HardDrive, 
  Layers, 
  Cpu, 
  PackageCheck, 
  Image, 
  DownloadCloud, 
  ChevronRight, 
  Check, 
  Clock, 
  FileText, 
  Folder, 
  Info, 
  Lock, 
  Unlock,
  AlertTriangle,
  RotateCcw,
  Sparkles
} from 'lucide-react';

interface MobileCleanerProps {
  onOpenOsintLab: () => void;
  onOpenSqlite: () => void;
  onOpenDocs: () => void;
}

export const MobileCleaner: React.FC<MobileCleanerProps> = ({
  onOpenOsintLab,
  onOpenSqlite,
  onOpenDocs,
}) => {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState('Tap Analyze to scan storage');
  const [scanProgress, setScanProgress] = useState(0);
  const [selectedCategory, setSelectedCategory] = useState<CategorySummary | null>(null);
  const [isCleaningAll, setIsCleaningAll] = useState(false);
  const [cleanedCategories, setCleanedCategories] = useState<Record<string, boolean>>({});
  const [cleaningMap, setCleaningMap] = useState<Record<string, boolean>>({});
  const [hasScopedStoragePermission, setHasScopedStoragePermission] = useState(true);
  
  // Threat confirmation modal
  const [pendingThreat, setPendingThreat] = useState<{
    threat: OsintThreatCheckResponse;
    categoryName: string;
    fileId?: string;
  } | null>(null);

  // Initial load
  useEffect(() => {
    // Perform initial diagnostic
    handleRunScan(true);
  }, []);

  const handleRunScan = async (silent = false) => {
    if (!silent) playSound('scan');
    setIsScanning(true);
    setScanProgress(5);

    const result = await storageEngine.runScan((stage, pct) => {
      setScanStage(stage);
      setScanProgress(pct);
    });

    setScanResult(result);
    setIsScanning(false);
    setCleanedCategories({});
    if (!silent) playSound('beep');
  };

  const handleCleanCategory = async (catName: string, forceConfirm = false) => {
    setCleaningMap(prev => ({ ...prev, [catName]: true }));
    playSound('clean');

    const res = await storageEngine.cleanCategory(catName, forceConfirm);

    if (res.status === 'warning' && res.requires_confirmation && res.threat_info) {
      playSound('alert');
      setCleaningMap(prev => ({ ...prev, [catName]: false }));
      setPendingThreat({
        threat: res.threat_info,
        categoryName: catName,
      });
      return;
    }

    setCleaningMap(prev => ({ ...prev, [catName]: false }));
    setCleanedCategories(prev => ({ ...prev, [catName]: true }));
    playSound('success');

    // Update state
    if (scanResult && scanResult.categories[catName]) {
      const freedBytes = res.bytes_freed;
      const freedFiles = res.files_removed;
      scanResult.total_bytes = Math.max(0, scanResult.total_bytes - freedBytes);
      scanResult.total_files = Math.max(0, scanResult.total_files - freedFiles);
      scanResult.categories[catName].count = 0;
      scanResult.categories[catName].size = 0;
      scanResult.categories[catName].files = [];
      setScanResult({ ...scanResult });
    }

    if (selectedCategory && selectedCategory.name === catName) {
      setSelectedCategory(null);
    }
  };

  const handleDeleteSingleFile = async (file: JunkFile, catName: string) => {
    // Check threat if malicious
    if (file.riskLevel === 'malicious' || file.riskLevel === 'suspicious') {
      const threatCheck = await storageEngine.checkFileThreat(file.hashSha256 || file.hashMd5, file.name);
      if (threatCheck.is_malicious) {
        playSound('alert');
        setPendingThreat({
          threat: threatCheck,
          categoryName: catName,
          fileId: file.id,
        });
        return;
      }
    }

    playSound('clean');
    storageEngine.deleteFile(file.id);
    playSound('pop');

    if (scanResult && scanResult.categories[catName]) {
      scanResult.categories[catName].files = scanResult.categories[catName].files.filter(f => f.id !== file.id);
      scanResult.categories[catName].count = scanResult.categories[catName].files.length;
      scanResult.categories[catName].size = Math.max(0, scanResult.categories[catName].size - file.size);
      scanResult.total_bytes = Math.max(0, scanResult.total_bytes - file.size);
      scanResult.total_files = Math.max(0, scanResult.total_files - 1);
      setScanResult({ ...scanResult });
      setSelectedCategory({ ...scanResult.categories[catName] });
    }
  };

  const handleCleanAll = async () => {
    // Check if any malicious files exist that need confirmation
    if (scanResult) {
      for (const [catName, cat] of Object.entries(scanResult.categories)) {
        const malFile = cat.files.find(f => f.riskLevel === 'malicious');
        if (malFile && !cleanedCategories[catName]) {
          const threatCheck = await storageEngine.checkFileThreat(malFile.hashSha256 || malFile.hashMd5, malFile.name);
          if (threatCheck.is_malicious) {
            playSound('alert');
            setPendingThreat({
              threat: threatCheck,
              categoryName: catName,
            });
            return;
          }
        }
      }
    }

    setIsCleaningAll(true);
    playSound('clean');
    await new Promise(r => setTimeout(r, 600));
    const result = await storageEngine.cleanAll();
    setIsCleaningAll(false);
    playSound('success');

    if (scanResult) {
      scanResult.total_bytes = 0;
      scanResult.total_files = 0;
      for (const cat of Object.values(scanResult.categories)) {
        cat.count = 0;
        cat.size = 0;
        cat.files = [];
      }
      setScanResult({ ...scanResult });
    }
  };

  const totalMb = scanResult ? (scanResult.total_bytes / (1024 * 1024)).toFixed(1) : '0.0';
  const totalGbStorage = 128;
  const simulatedUsedGb = 78.4;
  const storagePercentage = Math.round((simulatedUsedGb / totalGbStorage) * 100);

  const getCategoryIcon = (name: string) => {
    switch (name) {
      case 'App Cache': return <Layers className="w-4 h-4 text-cyan-400" />;
      case 'System Temp Files': return <Cpu className="w-4 h-4 text-purple-400" />;
      case 'Orphaned APKs': return <PackageCheck className="w-4 h-4 text-amber-400" />;
      case 'Thumbnail Cache': return <Image className="w-4 h-4 text-emerald-400" />;
      case 'Orphaned Downloads': return <DownloadCloud className="w-4 h-4 text-pink-400" />;
      default: return <Folder className="w-4 h-4 text-blue-400" />;
    }
  };

  return (
    <div className="flex-1 bg-slate-900 text-slate-100 flex flex-col font-sans select-none relative">
      
      {/* Native App Bar */}
      <div className="px-4 py-3 bg-slate-950/90 border-b border-slate-800/80 backdrop-blur-md sticky top-0 z-20 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
            <HardDrive className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-slate-100 tracking-tight flex items-center gap-1.5">
              DroidClean OSINT
              <span className="text-[9px] px-1 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
                PRO
              </span>
            </div>
            <div className="text-[10px] text-slate-400 font-mono">Android 14 (API 34)</div>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={onOpenOsintLab}
            title="OSINT Threat Intelligence Lab"
            className="p-1.5 rounded-lg bg-slate-800/90 border border-slate-700 text-amber-300 hover:text-amber-200 transition-colors"
          >
            <ShieldAlert className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={onOpenSqlite}
            title="SQLite Database & Rules"
            className="p-1.5 rounded-lg bg-slate-800/90 border border-slate-700 text-cyan-300 hover:text-white transition-colors"
          >
            <Clock className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Scoped Storage Permission Banner */}
      <div className="mx-3 mt-3 px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-[11px] flex items-center justify-between">
        <div className="flex items-center gap-2">
          {hasScopedStoragePermission ? (
            <Unlock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          ) : (
            <Lock className="w-3.5 h-3.5 text-rose-400 shrink-0" />
          )}
          <span className="text-slate-300">
            MANAGE_EXTERNAL_STORAGE: {hasScopedStoragePermission ? (
              <span className="text-emerald-400 font-semibold">Granted (Deep Scan)</span>
            ) : (
              <span className="text-rose-400 font-semibold">Sandbox Only</span>
            )}
          </span>
        </div>
        <button
          type="button"
          onClick={() => {
            playSound('pop');
            setHasScopedStoragePermission(!hasScopedStoragePermission);
          }}
          className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 hover:bg-slate-700"
        >
          Toggle
        </button>
      </div>

      {/* Main Storage Gauge Card */}
      <div className="p-4">
        <div className="relative rounded-3xl p-6 bg-gradient-to-b from-slate-800/90 via-slate-850 to-slate-900 border border-slate-700/80 shadow-2xl flex flex-col items-center text-center overflow-hidden">
          
          {/* Subtle Ambient Glow */}
          <div className="absolute -top-12 left-1/2 -translate-x-1/2 w-48 h-48 rounded-full bg-cyan-500/15 blur-3xl pointer-events-none" />

          {/* Circular SVG Storage Gauge */}
          <div className="relative w-44 h-44 my-2 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
              {/* Background Track */}
              <circle
                cx="50"
                cy="50"
                r="40"
                className="stroke-slate-800/80"
                strokeWidth="7"
                fill="none"
              />
              {/* Active Junk Indicator Ring */}
              <circle
                cx="50"
                cy="50"
                r="40"
                className={`${isScanning ? 'stroke-cyan-400 animate-pulse' : 'stroke-sky-500'} transition-all duration-700 ease-out`}
                strokeWidth="7"
                strokeDasharray="251.2"
                strokeDashoffset={isScanning ? 251.2 - (251.2 * scanProgress) / 100 : scanResult && scanResult.total_bytes > 0 ? 60 : 251.2}
                strokeLinecap="round"
                fill="none"
              />
            </svg>

            {/* Gauge Center Text */}
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-[10px] uppercase font-bold tracking-widest text-slate-400">
                {isScanning ? 'Analyzing' : 'Junk Space'}
              </span>
              <span className="text-3xl font-extrabold text-white tracking-tight mt-0.5 font-mono">
                {isScanning ? `${scanProgress}%` : `${totalMb}`}
              </span>
              <span className="text-[11px] font-semibold text-cyan-400">
                {isScanning ? 'Traversing' : 'MB Detected'}
              </span>
            </div>
          </div>

          {/* Scan Status Subtitle */}
          <p className="text-xs text-slate-400 h-5 truncate max-w-xs px-2 mb-4 font-mono">
            {isScanning ? scanStage : scanResult ? `${scanResult.total_files} junk items identified` : 'Ready to diagnose storage'}
          </p>

          {/* Primary Action Button Bar */}
          <div className="w-full grid grid-cols-2 gap-2.5">
            <button
              type="button"
              disabled={isScanning || isCleaningAll}
              onClick={() => handleRunScan(false)}
              className="py-3 px-3 rounded-2xl bg-slate-800 hover:bg-slate-750 active:scale-[0.98] border border-slate-700 text-slate-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all disabled:opacity-50 cursor-pointer shadow-md"
            >
              <Search className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-cyan-400' : 'text-slate-400'}`} />
              {isScanning ? 'Scanning...' : 'Re-Scan'}
            </button>

            <button
              type="button"
              disabled={isScanning || isCleaningAll || !scanResult || scanResult.total_bytes === 0}
              onClick={handleCleanAll}
              className="py-3 px-3 rounded-2xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 active:scale-[0.98] text-white text-xs font-bold flex items-center justify-center gap-1.5 transition-all disabled:opacity-40 cursor-pointer shadow-lg shadow-cyan-600/30"
            >
              <Trash2 className="w-3.5 h-3.5" />
              {isCleaningAll ? 'Cleaning...' : 'Clean All'}
            </button>
          </div>

        </div>
      </div>

      {/* Category Breakdown Header */}
      <div className="px-4 pb-2 flex items-center justify-between">
        <h6 className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
          Detected Cleanup Modules
        </h6>
        <span className="text-[10px] text-slate-500 font-mono">
          Rules: <span className="text-cyan-400">7 Active</span>
        </span>
      </div>

      {/* Category List */}
      <div className="px-4 pb-6 space-y-2 flex-1">
        {scanResult && Object.entries(scanResult.categories).map(([catName, cat]) => {
          const catMb = (cat.size / (1024 * 1024)).toFixed(1);
          const isDone = cleanedCategories[catName] || cat.count === 0;
          const isCleaning = cleaningMap[catName];
          const hasMalicious = cat.files.some(f => f.riskLevel === 'malicious');

          return (
            <div
              key={catName}
              className={`p-3 rounded-2xl bg-slate-950/80 border transition-all ${
                hasMalicious 
                  ? 'border-rose-900/60 hover:border-rose-700/80' 
                  : 'border-slate-800/90 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                
                {/* Left: Icon and info */}
                <div 
                  className="flex items-center gap-3 cursor-pointer flex-1 mr-2"
                  onClick={() => {
                    playSound('pop');
                    setSelectedCategory(cat);
                  }}
                >
                  <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
                    {getCategoryIcon(catName)}
                  </div>
                  <div>
                    <div className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                      {catName}
                      {hasMalicious && (
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-950 border border-rose-800 text-rose-300 font-mono font-normal">
                          OSINT Alert
                        </span>
                      )}
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      {isDone ? '0 files (Cleaned)' : `${cat.count} files · ${catMb} MB`}
                    </div>
                  </div>
                </div>

                {/* Right: Actions */}
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      playSound('pop');
                      setSelectedCategory(cat);
                    }}
                    title="Inspect file list"
                    className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-slate-900 transition-colors"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>

                  {isDone ? (
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-xl bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 text-[11px] font-semibold">
                      <Check className="w-3 h-3" />
                      Done
                    </span>
                  ) : (
                    <button
                      type="button"
                      disabled={isCleaning}
                      onClick={() => handleCleanCategory(catName)}
                      className={`px-3 py-1 rounded-xl text-[11px] font-bold transition-all disabled:opacity-40 cursor-pointer ${
                        hasMalicious
                          ? 'bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800'
                          : 'bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800'
                      }`}
                    >
                      {isCleaning ? 'Cleaning...' : 'Clean'}
                    </button>
                  )}
                </div>

              </div>
            </div>
          );
        })}
      </div>

      {/* Category File Inspector Drawer / Modal */}
      {selectedCategory && (
        <div className="fixed inset-0 z-40 flex items-end sm:items-center justify-center p-0 sm:p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-slate-900 border-t sm:border border-slate-700/80 rounded-t-3xl sm:rounded-3xl w-full max-w-md h-[80vh] flex flex-col overflow-hidden text-slate-100 shadow-2xl">
            
            {/* Header */}
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-slate-900 border border-slate-800">
                  {getCategoryIcon(selectedCategory.name)}
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-100">{selectedCategory.name}</h4>
                  <p className="text-[10px] text-slate-400">
                    {selectedCategory.files.length} items · {(selectedCategory.size / (1024 * 1024)).toFixed(1)} MB total
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedCategory(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            {/* Description */}
            <div className="px-5 py-2.5 bg-slate-950/60 border-b border-slate-800 text-[11px] text-slate-400">
              {selectedCategory.description}
            </div>

            {/* File List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
              {selectedCategory.files.length === 0 ? (
                <div className="text-center py-12 text-slate-500 text-xs">
                  All files in this category have been removed.
                </div>
              ) : (
                selectedCategory.files.map((file) => (
                  <div
                    key={file.id}
                    className={`p-3 rounded-xl border transition-colors ${
                      file.riskLevel === 'malicious'
                        ? 'bg-rose-950/30 border-rose-900/60'
                        : file.riskLevel === 'suspicious'
                        ? 'bg-amber-950/20 border-amber-900/50'
                        : 'bg-slate-950 border-slate-800'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1 overflow-hidden">
                        <div className="text-xs font-bold text-slate-200 truncate flex items-center gap-1.5">
                          {file.name}
                          {file.riskLevel === 'malicious' && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-950 border border-rose-800 text-rose-300 font-mono">
                              Threat Flagged
                            </span>
                          )}
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono truncate" title={file.path}>
                          {file.path}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono flex items-center gap-2">
                          <span>{(file.size / (1024 * 1024)).toFixed(1)} MB</span>
                          <span>·</span>
                          <span className="truncate">SHA: {file.hashSha256.substring(0, 12)}...</span>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => handleDeleteSingleFile(file, selectedCategory.name)}
                        className="p-2 rounded-lg bg-slate-900 hover:bg-rose-950/80 text-slate-400 hover:text-rose-400 border border-slate-800 hover:border-rose-800 transition-colors shrink-0"
                        title="Delete file"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    {file.threatDetails && (
                      <div className="mt-2 text-[10px] text-amber-400 bg-amber-950/30 p-1.5 rounded border border-amber-900/50">
                        {file.threatDetails}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
              <button
                type="button"
                onClick={() => setSelectedCategory(null)}
                className="px-4 py-2 rounded-xl border border-slate-700 bg-slate-800 text-slate-300 text-xs font-medium"
              >
                Close
              </button>
              <button
                type="button"
                disabled={selectedCategory.files.length === 0}
                onClick={() => handleCleanCategory(selectedCategory.name)}
                className="px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold disabled:opacity-40"
              >
                Purge Category ({selectedCategory.files.length} files)
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Malicious Warning Modal with OSINT details */}
      {pendingThreat && (
        <MaliciousWarningModal
          threat={pendingThreat.threat}
          onConfirmDelete={() => {
            const { categoryName, fileId } = pendingThreat;
            setPendingThreat(null);
            if (fileId) {
              storageEngine.deleteFile(fileId);
              playSound('clean');
              // Update state
              if (scanResult && scanResult.categories[categoryName]) {
                scanResult.categories[categoryName].files = scanResult.categories[categoryName].files.filter(f => f.id !== fileId);
                scanResult.categories[categoryName].count = scanResult.categories[categoryName].files.length;
                setScanResult({ ...scanResult });
              }
            } else {
              handleCleanCategory(categoryName, true);
            }
          }}
          onCancel={() => {
            setPendingThreat(null);
            playSound('pop');
          }}
        />
      )}

    </div>
  );
};
