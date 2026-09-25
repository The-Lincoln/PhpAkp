/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { AndroidFrame } from './components/AndroidFrame';
import { MobileCleaner } from './components/MobileCleaner';
import { BootstrapWebView } from './components/BootstrapWebView';
import { OsintInspector } from './components/OsintInspector';
import { SqliteManager } from './components/SqliteManager';
import { ArchitectureDocs } from './components/ArchitectureDocs';
import { storageEngine } from './services/storageSimulator';
import { playSound } from './utils/audio';
import { 
  Smartphone, 
  Globe, 
  ShieldAlert, 
  Database, 
  Code2, 
  RotateCcw, 
  Sparkles,
  HardDrive,
  Cpu,
  Layers,
  CheckCircle2,
  Terminal,
  Maximize2,
  Minimize2
} from 'lucide-react';

type MainView = 'mobile' | 'bootstrap' | 'osint' | 'sqlite' | 'code';

export default function App() {
  const [activeView, setActiveView] = useState<MainView>('mobile');
  const [useDeviceChassis, setUseDeviceChassis] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  const handleResetData = () => {
    playSound('clean');
    storageEngine.resetDemoData();
    setRefreshKey(prev => prev + 1);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      
      {/* Top Global Navigation Bar */}
      <header className="sticky top-0 z-50 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 px-4 lg:px-8 py-2.5 flex items-center justify-between">
        
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 p-0.5 shadow-lg shadow-cyan-600/20">
            <div className="h-full w-full rounded-[10px] bg-slate-950 flex items-center justify-center">
              <HardDrive className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold tracking-tight text-white">
                DroidClean Pro
              </h1>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/90 text-cyan-300 border border-cyan-800 font-mono font-medium">
                Android APK + OSINT
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              Mobile Storage Cleaner · SQLite Logging · VirusTotal Hash Verification
            </p>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center gap-1 p-1 rounded-2xl bg-slate-900 border border-slate-800">
          <button
            type="button"
            onClick={() => { setActiveView('mobile'); playSound('pop'); }}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeView === 'mobile' 
                ? 'bg-cyan-600 text-white shadow-md' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Smartphone className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Native Mobile UI</span>
          </button>

          <button
            type="button"
            onClick={() => { setActiveView('bootstrap'); playSound('pop'); }}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeView === 'bootstrap' 
                ? 'bg-cyan-600 text-white shadow-md' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Bootstrap 5 WebView</span>
          </button>

          <button
            type="button"
            onClick={() => { setActiveView('osint'); playSound('pop'); }}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeView === 'osint' 
                ? 'bg-cyan-600 text-white shadow-md' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span className="hidden md:inline">OSINT Threat Lab</span>
          </button>

          <button
            type="button"
            onClick={() => { setActiveView('sqlite'); playSound('pop'); }}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeView === 'sqlite' 
                ? 'bg-cyan-600 text-white shadow-md' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span className="hidden md:inline">SQLite & Rules</span>
          </button>

          <button
            type="button"
            onClick={() => { setActiveView('code'); playSound('pop'); }}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeView === 'code' 
                ? 'bg-cyan-600 text-white shadow-md' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Source & APK</span>
          </button>
        </div>

        {/* Global Controls */}
        <div className="flex items-center gap-2">
          {activeView === 'mobile' && (
            <button
              type="button"
              onClick={() => setUseDeviceChassis(!useDeviceChassis)}
              title={useDeviceChassis ? 'Switch to Fullscreen' : 'Show Smartphone Chassis'}
              className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors"
            >
              {useDeviceChassis ? <Maximize2 className="w-4 h-4" /> : <Minimize2 className="w-4 h-4" />}
            </button>
          )}

          <button
            type="button"
            onClick={handleResetData}
            title="Reset Mock Android Storage to Default"
            className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>

      </header>

      {/* Main View Area */}
      <main className="flex-1 flex flex-col overflow-hidden">
        
        {/* VIEW 1: Native Mobile Cleaner */}
        {activeView === 'mobile' && (
          <div className="flex-1 overflow-y-auto py-6 px-4 flex items-center justify-center">
            {useDeviceChassis ? (
              <AndroidFrame key={`phone-${refreshKey}`}>
                <MobileCleaner
                  key={`cleaner-${refreshKey}`}
                  onOpenOsintLab={() => setActiveView('osint')}
                  onOpenSqlite={() => setActiveView('sqlite')}
                  onOpenDocs={() => setActiveView('code')}
                />
              </AndroidFrame>
            ) : (
              <div className="w-full max-w-2xl h-[820px] rounded-3xl bg-slate-900 border border-slate-800 overflow-hidden shadow-2xl flex flex-col">
                <MobileCleaner
                  key={`cleaner-full-${refreshKey}`}
                  onOpenOsintLab={() => setActiveView('osint')}
                  onOpenSqlite={() => setActiveView('sqlite')}
                  onOpenDocs={() => setActiveView('code')}
                />
              </div>
            )}
          </div>
        )}

        {/* VIEW 2: Bootstrap 5 WebView Mode (Exact prompt implementation) */}
        {activeView === 'bootstrap' && (
          <div className="flex-1 overflow-y-auto py-6 px-4 flex flex-col items-center justify-center">
            <div className="w-full max-w-md h-[800px] rounded-3xl bg-slate-900 border border-slate-800 overflow-hidden shadow-2xl flex flex-col">
              <BootstrapWebView
                key={`b5-${refreshKey}`}
                onOpenOsintModal={() => setActiveView('osint')}
                onRefreshParent={() => setRefreshKey(prev => prev + 1)}
              />
            </div>
          </div>
        )}

        {/* VIEW 3: OSINT Threat Intelligence & Hash Auditor */}
        {activeView === 'osint' && (
          <div className="flex-1 flex flex-col">
            <OsintInspector key={`osint-${refreshKey}`} />
          </div>
        )}

        {/* VIEW 4: SQLite Database & Rules Manager */}
        {activeView === 'sqlite' && (
          <div className="flex-1 flex flex-col">
            <SqliteManager key={`sqlite-${refreshKey}`} />
          </div>
        )}

        {/* VIEW 5: Code Repository & APK Architecture */}
        {activeView === 'code' && (
          <div className="flex-1 flex flex-col">
            <ArchitectureDocs />
          </div>
        )}

      </main>

    </div>
  );
}
