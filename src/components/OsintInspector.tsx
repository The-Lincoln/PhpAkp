import React, { useState } from 'react';
import { storageEngine } from '../services/storageSimulator';
import { OsintReport, OsintThreatCheckResponse } from '../types';
import { playSound } from '../utils/audio';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  AlertTriangle, 
  Terminal, 
  Copy, 
  Check, 
  FileCode, 
  Fingerprint, 
  Radio, 
  Lock, 
  Zap, 
  CheckCircle, 
  ExternalLink,
  PlusCircle,
  Hash,
  Database,
  Trash2,
  RefreshCw,
  ClipboardPaste,
  XCircle,
  HelpCircle,
  Activity
} from 'lucide-react';

export const OsintInspector: React.FC = () => {
  const [reports] = useState<OsintReport[]>(storageEngine.getOsintReports());
  const [selectedReport, setSelectedReport] = useState<OsintReport>(reports[0]);
  
  // Custom hash input state
  const [hashInput, setHashInput] = useState('3a52e07198e3b26c2e3612502efae8eb3595cfad7e1f4094a9a957d1976a26df');
  const [isQuerying, setIsQuerying] = useState(false);
  const [activeReportResult, setActiveReportResult] = useState<OsintThreatCheckResponse | null>(null);
  const [recentQueries, setRecentQueries] = useState<string[]>([
    '3a52e07198e3b26c2e3612502efae8eb3595cfad7e1f4094a9a957d1976a26df',
    'd7a8fbb307d7809469ca9ab5d0fed30e',
    '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',
    '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
  ]);
  const [copiedHash, setCopiedHash] = useState(false);
  const [ruleAddedSuccess, setRuleAddedSuccess] = useState<string | null>(null);

  // Detect format of entered hash
  const getHashAlgorithm = (str: string) => {
    const clean = str.trim();
    if (!clean) return null;
    if (/^[a-f0-9]{32}$/i.test(clean)) return { name: 'MD5', length: 32, color: 'text-amber-400 bg-amber-950/60 border-amber-800' };
    if (/^[a-f0-9]{40}$/i.test(clean)) return { name: 'SHA-1', length: 40, color: 'text-purple-400 bg-purple-950/60 border-purple-800' };
    if (/^[a-f0-9]{64}$/i.test(clean)) return { name: 'SHA-256', length: 64, color: 'text-cyan-400 bg-cyan-950/60 border-cyan-800' };
    return { name: 'Custom String', length: clean.length, color: 'text-slate-400 bg-slate-900 border-slate-700' };
  };

  const detectedAlgo = getHashAlgorithm(hashInput);

  const handleQueryHash = async (hashToQuery: string) => {
    const trimmed = hashToQuery.trim();
    if (!trimmed) return;
    setIsQuerying(true);
    setRuleAddedSuccess(null);
    playSound('scan');

    const result = await storageEngine.checkFileThreat(trimmed);
    setActiveReportResult(result);
    setIsQuerying(false);
    playSound(result.is_malicious ? 'alert' : 'success');

    if (!recentQueries.includes(trimmed)) {
      setRecentQueries(prev => [trimmed, ...prev.slice(0, 5)]);
    }
  };

  const handlePasteClipboard = async () => {
    try {
      if (navigator.clipboard) {
        const text = await navigator.clipboard.readText();
        if (text) {
          setHashInput(text.trim());
          playSound('pop');
        }
      }
    } catch {
      // Ignore clipboard permission restriction gracefully
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    playSound('pop');
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleAddRuleFromThreat = (threat: OsintThreatCheckResponse) => {
    const pattern = threat.suggestedRulePattern || `*${threat.hash.substring(0, 8)}*`;
    const ruleName = `OSINT Block: ${threat.threat_name || 'Flagged Binary'}`;
    storageEngine.addRule(ruleName, pattern, 1, `Auto-generated rule from VirusTotal query (${threat.detection_ratio})`);
    playSound('success');
    setRuleAddedSuccess(`Successfully added rule: ${pattern} (is_malicious = 1)`);
    setTimeout(() => setRuleAddedSuccess(null), 4000);
  };

  return (
    <div className="flex-1 bg-slate-900 text-slate-100 flex flex-col p-4 sm:p-6 overflow-y-auto font-sans">
      
      {/* Top Banner Header */}
      <div className="mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/30">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-white tracking-tight flex items-center gap-2">
                OSINT Threat Intelligence & Hash Auditor
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono">
                  VirusTotal v3 Database
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Audit file hashes (MD5 / SHA-256) against global threat intelligence feeds and security vendors
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] px-3 py-1 rounded-full bg-slate-950 border border-slate-800 text-slate-300 font-mono flex items-center gap-1.5 shadow-sm">
            <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
            72 Security Vendor Engines Connected
          </span>
        </div>
      </div>

      {/* Main Hash Query Console Box */}
      <div className="mb-6 p-5 rounded-2xl bg-slate-950 border border-slate-800 shadow-xl">
        <div className="flex items-center justify-between mb-2.5">
          <label className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Hash className="w-4 h-4 text-cyan-400" />
            Paste File Hash (MD5 / SHA-1 / SHA-256)
          </label>
          {detectedAlgo && (
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-md border ${detectedAlgo.color}`}>
              Format: {detectedAlgo.name} ({detectedAlgo.length} hex chars)
            </span>
          )}
        </div>

        {/* Input & Search Group */}
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              placeholder="Paste MD5 (32 chars) or SHA-256 (64 chars) to query VirusTotal intelligence..."
              className="w-full pl-4 pr-24 py-3 rounded-xl bg-slate-900 border border-slate-700/80 text-xs font-mono text-cyan-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 shadow-inner"
            />
            <div className="absolute right-2 top-2.5 flex items-center gap-1">
              {hashInput && (
                <button
                  type="button"
                  onClick={() => setHashInput('')}
                  title="Clear input"
                  className="p-1 text-slate-500 hover:text-slate-300"
                >
                  <XCircle className="w-3.5 h-3.5" />
                </button>
              )}
              <button
                type="button"
                onClick={handlePasteClipboard}
                title="Paste from clipboard"
                className="px-2 py-1 rounded bg-slate-800 text-[10px] text-slate-300 hover:bg-slate-700 flex items-center gap-1 border border-slate-700 font-mono"
              >
                <ClipboardPaste className="w-3 h-3" />
                Paste
              </button>
            </div>
          </div>

          <button
            type="button"
            disabled={isQuerying || !hashInput.trim()}
            onClick={() => handleQueryHash(hashInput)}
            className="py-3 px-6 rounded-xl bg-gradient-to-r from-amber-500 via-rose-600 to-red-600 hover:from-amber-400 hover:to-red-500 text-white font-bold text-xs flex items-center justify-center gap-2 disabled:opacity-40 transition-all cursor-pointer shadow-lg shadow-rose-950/40 shrink-0"
          >
            <Search className={`w-4 h-4 ${isQuerying ? 'animate-spin' : ''}`} />
            {isQuerying ? 'Querying Threat DB...' : 'Query VirusTotal'}
          </button>
        </div>

        {/* Quick Sample Presets */}
        <div className="mt-3.5 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
          <span className="font-semibold text-slate-300">Preset Samples:</span>
          
          <button
            type="button"
            onClick={() => {
              const h = '3a52e07198e3b26c2e3612502efae8eb3595cfad7e1f4094a9a957d1976a26df';
              setHashInput(h);
              handleQueryHash(h);
            }}
            className="px-2.5 py-1 rounded-lg bg-rose-950/40 text-rose-300 border border-rose-800/80 hover:bg-rose-900/60 font-mono cursor-pointer transition-colors"
          >
            SHA256: Adware Dropper (34/72)
          </button>

          <button
            type="button"
            onClick={() => {
              const h = 'd7a8fbb307d7809469ca9ab5d0fed30e';
              setHashInput(h);
              handleQueryHash(h);
            }}
            className="px-2.5 py-1 rounded-lg bg-rose-950/40 text-rose-300 border border-rose-800/80 hover:bg-rose-900/60 font-mono cursor-pointer transition-colors"
          >
            MD5: Adware Dropper (34/72)
          </button>

          <button
            type="button"
            onClick={() => {
              const h = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918';
              setHashInput(h);
              handleQueryHash(h);
            }}
            className="px-2.5 py-1 rounded-lg bg-amber-950/40 text-amber-300 border border-amber-800/80 hover:bg-amber-900/60 font-mono cursor-pointer transition-colors"
          >
            SHA256: Fake Booster PUA (14/72)
          </button>

          <button
            type="button"
            onClick={() => {
              const h = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b';
              setHashInput(h);
              handleQueryHash(h);
            }}
            className="px-2.5 py-1 rounded-lg bg-emerald-950/40 text-emerald-300 border border-emerald-800/80 hover:bg-emerald-900/60 font-mono cursor-pointer transition-colors"
          >
            SHA256: Clean VideoLAN VLC (0/72)
          </button>
        </div>

      </div>

      {/* Query Result Card / Threat Intelligence Output */}
      {activeReportResult && (
        <div className="mb-6 rounded-2xl bg-slate-950 border border-slate-800 shadow-xl overflow-hidden animate-in fade-in duration-200">
          
          {/* Header Status Bar */}
          <div className={`p-4 border-b flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
            activeReportResult.is_malicious 
              ? 'bg-rose-950/60 border-rose-800/80 text-rose-100' 
              : 'bg-emerald-950/60 border-emerald-800/80 text-emerald-100'
          }`}>
            <div className="flex items-center gap-3">
              <div className={`p-2.5 rounded-xl border ${
                activeReportResult.is_malicious 
                  ? 'bg-rose-900/60 border-rose-700 text-rose-300 animate-pulse' 
                  : 'bg-emerald-900/60 border-emerald-700 text-emerald-300'
              }`}>
                {activeReportResult.is_malicious ? (
                  <AlertTriangle className="w-5 h-5" />
                ) : (
                  <CheckCircle className="w-5 h-5" />
                )}
              </div>
              <div>
                <div className="text-sm font-bold flex items-center gap-2">
                  {activeReportResult.threat_name}
                  {activeReportResult.is_malicious ? (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-900 text-rose-200 font-mono font-bold">
                      MALICIOUS THREAT
                    </span>
                  ) : (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-900 text-emerald-200 font-mono font-bold">
                      SAFE & CLEAN
                    </span>
                  )}
                </div>
                <p className="text-xs opacity-90 mt-0.5">{activeReportResult.details}</p>
              </div>
            </div>

            {/* Action button */}
            {activeReportResult.is_malicious && (
              <button
                type="button"
                onClick={() => handleAddRuleFromThreat(activeReportResult)}
                className="px-3.5 py-2 rounded-xl bg-rose-700 hover:bg-rose-600 text-white font-bold text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-md shrink-0"
              >
                <PlusCircle className="w-4 h-4" />
                Add to clean_rules (is_malicious = 1)
              </button>
            )}
          </div>

          {/* Rule added toast feedback */}
          {ruleAddedSuccess && (
            <div className="px-4 py-2 bg-emerald-950 text-emerald-300 text-xs font-mono border-b border-emerald-800 flex items-center gap-2">
              <Check className="w-4 h-4" />
              {ruleAddedSuccess}
            </div>
          )}

          {/* Body Telemetry */}
          <div className="p-5 space-y-5">
            
            {/* 3 Metric Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400">Security Vendors</span>
                <div className={`text-xl font-extrabold font-mono mt-0.5 ${
                  activeReportResult.is_malicious ? 'text-rose-400' : 'text-emerald-400'
                }`}>
                  {activeReportResult.detection_ratio}
                </div>
                <span className="text-[10px] text-slate-500">Engines flagged this hash</span>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400">Threat Severity Score</span>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className={`text-xl font-extrabold font-mono ${
                    activeReportResult.threat_score && activeReportResult.threat_score > 50 ? 'text-rose-400' : activeReportResult.threat_score && activeReportResult.threat_score > 20 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {activeReportResult.threat_score ?? 0} / 100
                  </span>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-1.5 overflow-hidden">
                  <div 
                    className={`h-full ${
                      activeReportResult.threat_score && activeReportResult.threat_score > 50 ? 'bg-rose-500' : activeReportResult.threat_score && activeReportResult.threat_score > 20 ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${activeReportResult.threat_score ?? 0}%` }}
                  />
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400">Community Reputation</span>
                <div className={`text-xl font-extrabold font-mono mt-0.5 ${
                  (activeReportResult.community_reputation ?? 0) < 0 ? 'text-rose-400' : 'text-emerald-400'
                }`}>
                  {activeReportResult.community_reputation ?? 0}
                </div>
                <span className="text-[10px] text-slate-500">Crowdsourced threat trust score</span>
              </div>
            </div>

            {/* Hash Details Strip */}
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-2 overflow-hidden">
                <span className="text-slate-400 font-semibold uppercase text-[10px]">Queried Hash:</span>
                <span className="font-mono text-cyan-300 truncate select-all">{activeReportResult.hash}</span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(activeReportResult.hash)}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 shrink-0 cursor-pointer"
              >
                {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedHash ? 'Copied' : 'Copy Hash'}
              </button>
            </div>

            {/* Vendor Breakdown Table */}
            {activeReportResult.vendors && activeReportResult.vendors.length > 0 && (
              <div className="space-y-2">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Antivirus Vendor Telemetry Detections
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                  {activeReportResult.vendors.map((v, i) => (
                    <div
                      key={i}
                      className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div>
                        <div className="font-semibold text-slate-200">{v.vendor}</div>
                        <div className="text-[10px] font-mono text-slate-400 truncate max-w-[140px]">
                          {v.signature}
                        </div>
                      </div>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                        v.result === 'malicious'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : v.result === 'suspicious'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      }`}>
                        {v.result}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Heuristic Signatures */}
            {activeReportResult.signatures && activeReportResult.signatures.length > 0 && (
              <div className="space-y-2">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Extracted Indicators & Android Privileges
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {activeReportResult.signatures.map((sig, i) => (
                    <span
                      key={i}
                      className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5"
                    >
                      <Lock className="w-3 h-3 text-amber-400" />
                      {sig}
                    </span>
                  ))}
                </div>
              </div>
            )}

          </div>

        </div>
      )}

      {/* Discovered APKs in Storage Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Detected Storage Binaries & Installed APK Files ({reports.length})
          </h3>
          <span className="text-[11px] text-slate-400">Click any file to load its hash directly</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          {reports.map((rep) => {
            const isTarget = hashInput.toLowerCase() === rep.sha256.toLowerCase() || hashInput.toLowerCase() === rep.md5.toLowerCase();
            return (
              <div
                key={rep.id}
                onClick={() => {
                  setHashInput(rep.sha256);
                  handleQueryHash(rep.sha256);
                  setSelectedReport(rep);
                  playSound('pop');
                }}
                className={`p-4 rounded-2xl border cursor-pointer transition-all ${
                  isTarget
                    ? 'bg-slate-800 border-cyan-500 shadow-lg shadow-cyan-950/40'
                    : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="text-xs font-bold text-slate-100 flex items-center gap-2">
                      {rep.fileName}
                      {rep.riskLevel === 'malicious' && (
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-950 border border-rose-800 text-rose-300 font-mono font-normal">
                          THREAT
                        </span>
                      )}
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono">
                      Pkg: {rep.packageName}
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono truncate" title={rep.sha256}>
                      SHA: {rep.sha256.substring(0, 16)}...
                    </div>
                  </div>

                  <div className={`text-xs font-mono font-bold ${
                    rep.riskLevel === 'malicious' ? 'text-rose-400' : rep.riskLevel === 'suspicious' ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {rep.detectionRatio}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
