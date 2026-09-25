import React, { useState } from 'react';
import { OsintThreatCheckResponse } from '../types';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Trash2, 
  X, 
  Check, 
  Copy, 
  ExternalLink, 
  Lock, 
  FileWarning 
} from 'lucide-react';
import { playSound } from '../utils/audio';

interface MaliciousWarningModalProps {
  threat: OsintThreatCheckResponse;
  onConfirmDelete: () => void;
  onCancel: () => void;
}

export const MaliciousWarningModal: React.FC<MaliciousWarningModalProps> = ({
  threat,
  onConfirmDelete,
  onCancel,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopyHash = () => {
    navigator.clipboard.writeText(threat.hash);
    setCopied(true);
    playSound('pop');
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-slate-900 border-2 border-rose-500/80 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl shadow-rose-950/60 flex flex-col text-slate-100">
        
        {/* Urgent Warning Header */}
        <div className="bg-gradient-to-r from-rose-950/90 via-red-900/80 to-slate-950 px-5 py-4 border-b border-rose-800/60 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-400 animate-pulse">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-rose-200 tracking-wide uppercase">
                OSINT Threat Detected
              </h4>
              <p className="text-[11px] text-rose-300/80">User confirmation required before purge</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onCancel}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800/80 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Threat Details Content */}
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          
          {/* Main Threat Badge Card */}
          <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-800/50 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="text-xs font-semibold text-rose-300">
                {threat.threat_name || 'Generic Suspicious Android Binary'}
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                {threat.details || 'This file matches known threat signatures or requests high-risk Android system privileges.'}
              </p>
            </div>
          </div>

          {/* VirusTotal Detection Score */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">VirusTotal OSINT</span>
              <span className="text-base font-bold text-rose-400 font-mono mt-0.5">
                {threat.detection_ratio || 'Flagged'}
              </span>
              <span className="text-[10px] text-slate-500">Security Vendors Alerted</span>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Target File</span>
              <span className="text-xs font-semibold text-slate-200 truncate mt-0.5">
                {threat.fileName}
              </span>
              <span className="text-[10px] text-slate-500">{threat.category}</span>
            </div>
          </div>

          {/* SHA-256 Hash Display */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>Cryptographic Hash (SHA-256)</span>
              <button
                type="button"
                onClick={handleCopyHash}
                className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied' : 'Copy Hash'}
              </button>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 break-all select-all">
              {threat.hash}
            </div>
          </div>

          {/* Suspicious Signatures or Permissions */}
          {threat.signatures && threat.signatures.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                Flagged Android Indicators & Permissions
              </span>
              <div className="space-y-1">
                {threat.signatures.map((sig, i) => (
                  <div key={i} className="flex items-center gap-2 text-[11px] px-2.5 py-1.5 rounded-md bg-slate-950/70 border border-slate-800 text-slate-300 font-mono">
                    <Lock className="w-3 h-3 text-amber-400 shrink-0" />
                    <span className="truncate">{sig}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-800/40 text-[11px] text-amber-300 flex items-start gap-2">
            <FileWarning className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <span>
              Deleting this file will completely purge it from local device storage and record the deletion to SQLite <code className="text-cyan-300 font-mono">cleanup_logs</code>.
            </span>
          </div>

        </div>

        {/* Action Buttons */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex items-center gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="flex-1 py-2.5 px-4 rounded-xl border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors cursor-pointer"
          >
            Cancel & Keep
          </button>
          <button
            type="button"
            onClick={() => {
              playSound('clean');
              onConfirmDelete();
            }}
            className="flex-1 py-2.5 px-4 rounded-xl bg-gradient-to-r from-rose-600 to-red-700 hover:from-rose-500 hover:to-red-600 text-white text-xs font-bold shadow-lg shadow-rose-950/50 flex items-center justify-center gap-1.5 transition-all cursor-pointer"
          >
            <Trash2 className="w-4 h-4" />
            Confirm Deletion
          </button>
        </div>

      </div>
    </div>
  );
};
