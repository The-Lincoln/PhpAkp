import React, { useState, useEffect } from 'react';
import { storageEngine } from '../services/storageSimulator';
import { CleanRule, CleanupLog } from '../types';
import { playSound } from '../utils/audio';
import { 
  Database, 
  Table, 
  Terminal, 
  Plus, 
  Trash2, 
  Check, 
  Clock, 
  ShieldAlert, 
  ShieldCheck, 
  Play, 
  FileSpreadsheet, 
  RotateCcw,
  Sparkles
} from 'lucide-react';

export const SqliteManager: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'rules' | 'logs' | 'query'>('rules');
  const [rules, setRules] = useState<CleanRule[]>([]);
  const [logs, setLogs] = useState<CleanupLog[]>([]);
  
  // New rule form
  const [newRuleName, setNewRuleName] = useState('');
  const [newRulePattern, setNewRulePattern] = useState('');
  const [newRuleIsMalicious, setNewRuleIsMalicious] = useState(false);
  const [newRuleDesc, setNewRuleDesc] = useState('');

  // SQL Console
  const [sqlQuery, setSqlQuery] = useState('SELECT * FROM clean_rules WHERE is_malicious = 1;');
  const [queryResult, setQueryResult] = useState<{
    columns?: string[];
    rows?: Record<string, unknown>[];
    message?: string;
    rowCount?: number;
    success?: boolean;
  } | null>(null);

  useEffect(() => {
    refreshData();
  }, []);

  const refreshData = () => {
    setRules(storageEngine.getRules());
    setLogs(storageEngine.getLogs());
  };

  const handleToggleRule = (id: number) => {
    storageEngine.toggleRule(id);
    playSound('pop');
    refreshData();
  };

  const handleToggleMalicious = (id: number) => {
    storageEngine.toggleRuleMalicious(id);
    playSound('pop');
    refreshData();
  };

  const handleDeleteRule = (id: number) => {
    storageEngine.deleteRule(id);
    playSound('clean');
    refreshData();
  };

  const handleAddRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName.trim() || !newRulePattern.trim()) return;

    storageEngine.addRule(
      newRuleName.trim(), 
      newRulePattern.trim(), 
      newRuleIsMalicious ? 1 : 0, 
      newRuleDesc.trim() || undefined
    );
    playSound('success');
    setNewRuleName('');
    setNewRulePattern('');
    setNewRuleDesc('');
    setNewRuleIsMalicious(false);
    refreshData();
  };

  const handleRunQuery = (queryToRun?: string) => {
    const q = queryToRun || sqlQuery;
    playSound('beep');
    const res = storageEngine.executeSql(q);
    setQueryResult(res);
  };

  return (
    <div className="flex-1 bg-slate-900 text-slate-100 flex flex-col p-4 sm:p-6 overflow-y-auto font-sans">
      
      {/* Top Header */}
      <div className="mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base sm:text-lg font-bold text-white tracking-tight flex items-center gap-2">
              SQLite Database Inspector
              <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono">
                storage_cleaner.db
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Direct access to clean_rules (with is_malicious flag) and cleanup_logs tables
            </p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-950 border border-slate-800">
          <button
            type="button"
            onClick={() => { setActiveTab('rules'); playSound('pop'); }}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'rules' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            clean_rules ({rules.length})
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab('logs'); playSound('pop'); }}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'logs' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            cleanup_logs ({logs.length})
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab('query'); playSound('pop'); }}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 ${
              activeTab === 'query' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            SQL Console
          </button>
        </div>
      </div>

      {/* Tab: clean_rules */}
      {activeTab === 'rules' && (
        <div className="space-y-6">
          
          {/* Add New Rule Card */}
          <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 shadow-md">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-1.5">
              <Plus className="w-4 h-4 text-cyan-400" />
              Add Rule with is_malicious Security Flag
            </h3>

            <form onSubmit={handleAddRule} className="grid grid-cols-1 sm:grid-cols-12 gap-3">
              <div className="sm:col-span-4">
                <label className="block text-[11px] text-slate-400 mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Sideloaded APKs or Malicious Dex"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="sm:col-span-4">
                <label className="block text-[11px] text-slate-400 mb-1">Target Glob Pattern</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. *.dex.enc or downloads/*.apk"
                  value={newRulePattern}
                  onChange={(e) => setNewRulePattern(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="sm:col-span-4 flex flex-col justify-end">
                <label className="flex items-center gap-2 mb-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={newRuleIsMalicious}
                    onChange={(e) => setNewRuleIsMalicious(e.target.checked)}
                    className="w-4 h-4 rounded text-rose-600 bg-slate-900 border-slate-700 focus:ring-0"
                  />
                  <span className="text-xs font-semibold text-rose-300">
                    Flag as is_malicious (Trigger OSINT VirusTotal check)
                  </span>
                </label>

                <button
                  type="submit"
                  className="w-full py-2 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition-colors cursor-pointer flex items-center justify-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Insert Rule into SQLite
                </button>
              </div>
            </form>
          </div>

          {/* Rules Table */}
          <div className="rounded-2xl border border-slate-800 bg-slate-950 overflow-hidden shadow-lg">
            <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Table: clean_rules
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                Columns: id, rule_name, target_pattern, is_active, is_malicious
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3 font-mono">ID</th>
                    <th className="px-4 py-3">Rule Name</th>
                    <th className="px-4 py-3 font-mono">Target Pattern</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">is_malicious Flag</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {rules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="px-4 py-3 font-mono text-slate-500">{rule.id}</td>
                      <td className="px-4 py-3 font-semibold text-slate-200">
                        {rule.rule_name}
                        {rule.description && (
                          <div className="text-[10px] text-slate-500 font-normal mt-0.5">{rule.description}</div>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-cyan-400">
                        <code className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                          {rule.target_pattern}
                        </code>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          type="button"
                          onClick={() => handleToggleRule(rule.id)}
                          className={`px-2.5 py-1 rounded-full text-[10px] font-bold cursor-pointer transition-colors ${
                            rule.is_active === 1
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}
                        >
                          {rule.is_active === 1 ? 'Active (1)' : 'Disabled (0)'}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          type="button"
                          onClick={() => handleToggleMalicious(rule.id)}
                          title="Click to toggle is_malicious flag"
                          className={`px-2.5 py-1 rounded-full text-[10px] font-bold cursor-pointer transition-colors flex items-center gap-1.5 w-fit ${
                            rule.is_malicious === 1
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-slate-900 text-slate-400 border border-slate-800'
                          }`}
                        >
                          {rule.is_malicious === 1 ? (
                            <>
                              <ShieldAlert className="w-3 h-3 text-rose-400" />
                              Malicious (1)
                            </>
                          ) : (
                            <>
                              <ShieldCheck className="w-3 h-3 text-slate-500" />
                              Standard (0)
                            </>
                          )}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => handleDeleteRule(rule.id)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-slate-900 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab: cleanup_logs */}
      {activeTab === 'logs' && (
        <div className="rounded-2xl border border-slate-800 bg-slate-950 overflow-hidden shadow-lg">
          <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Table: cleanup_logs
            </span>
            <span className="text-[11px] text-slate-400 font-mono">
              Total Operations: {logs.length}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3 font-mono">ID</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3 text-right">Files Removed</th>
                  <th className="px-4 py-3 text-right">Bytes Freed</th>
                  <th className="px-4 py-3 text-right">Cleaned At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                      No logs recorded in SQLite yet.
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="px-4 py-3 font-mono text-slate-500">{log.id}</td>
                      <td className="px-4 py-3 font-semibold text-slate-200">{log.category}</td>
                      <td className="px-4 py-3 text-right font-mono text-slate-300">{log.files_removed}</td>
                      <td className="px-4 py-3 text-right font-mono text-cyan-400 font-bold">
                        {(log.bytes_freed / (1024 * 1024)).toFixed(1)} MB
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-slate-400 text-[11px]">
                        {log.cleaned_at}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab: SQL Console */}
      {activeTab === 'query' && (
        <div className="space-y-4">
          <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-300">
                SQLite 3 Terminal (In-Memory Engine)
              </label>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    const q = 'SELECT * FROM clean_rules WHERE is_malicious = 1;';
                    setSqlQuery(q);
                    handleRunQuery(q);
                  }}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-rose-300 border border-slate-800 hover:bg-slate-800"
                >
                  WHERE is_malicious = 1
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const q = 'SELECT SUM(bytes_freed) FROM cleanup_logs;';
                    setSqlQuery(q);
                    handleRunQuery(q);
                  }}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-800 hover:bg-slate-800"
                >
                  SUM(bytes_freed)
                </button>
              </div>
            </div>

            <textarea
              rows={3}
              value={sqlQuery}
              onChange={(e) => setSqlQuery(e.target.value)}
              className="w-full p-3 rounded-xl bg-slate-900 border border-slate-700 font-mono text-xs text-cyan-300 focus:outline-none focus:border-cyan-500"
            />

            <div className="mt-3 flex justify-end">
              <button
                type="button"
                onClick={() => handleRunQuery()}
                className="py-2 px-5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-xs flex items-center gap-2 shadow-md cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                Execute SQL
              </button>
            </div>
          </div>

          {/* Query Results */}
          {queryResult && (
            <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-3 text-xs">
                <span className="font-bold text-slate-300">Execution Result</span>
                <span className="text-slate-500 font-mono">{queryResult.rowCount ?? 0} rows affected</span>
              </div>

              {queryResult.message && (
                <div className={`p-3 rounded-lg text-xs font-mono mb-3 ${
                  queryResult.success ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800' : 'bg-rose-950/60 text-rose-300 border border-rose-800'
                }`}>
                  {queryResult.message}
                </div>
              )}

              {queryResult.columns && queryResult.rows && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                      <tr>
                        {queryResult.columns.map((c) => (
                          <th key={c} className="px-3 py-2">{c}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {queryResult.rows.map((row, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          {queryResult.columns!.map((c) => (
                            <td key={c} className="px-3 py-2 text-slate-200">
                              {String(row[c] ?? 'NULL')}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

    </div>
  );
};
