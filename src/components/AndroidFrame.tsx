import React from 'react';
import { Wifi, Battery, Signal, ArrowLeft, Home, Square } from 'lucide-react';

interface AndroidFrameProps {
  children: React.ReactNode;
  currentTime?: string;
  isWebViewMode?: boolean;
}

export const AndroidFrame: React.FC<AndroidFrameProps> = ({
  children,
  currentTime = '10:24',
  isWebViewMode = false,
}) => {
  return (
    <div className="relative mx-auto flex flex-col items-center justify-center">
      {/* Outer Phone Shell */}
      <div className="relative w-full max-w-[420px] rounded-[48px] bg-slate-950 p-[10px] shadow-2xl shadow-cyan-950/40 ring-1 ring-slate-800/80 transition-all duration-300">
        {/* Metal Side Frame Highlights & Buttons */}
        <div className="absolute -left-[3px] top-28 h-12 w-[3px] rounded-l-sm bg-slate-700/80" />
        <div className="absolute -left-[3px] top-44 h-16 w-[3px] rounded-l-sm bg-slate-700/80" />
        <div className="absolute -right-[3px] top-32 h-14 w-[3px] rounded-r-sm bg-slate-700/80" />

        {/* Screen Bezel */}
        <div className="relative flex flex-col h-[780px] w-full overflow-hidden rounded-[38px] bg-slate-900 border border-slate-800/90 text-slate-100 select-none">
          
          {/* Status Bar */}
          <div className="relative z-30 flex items-center justify-between px-6 pt-3 pb-2 text-xs font-medium text-slate-300 backdrop-blur-sm bg-slate-950/40">
            {/* Clock */}
            <span className="font-semibold tracking-tight text-slate-200">{currentTime}</span>

            {/* Camera Cutout (Hole punch) */}
            <div className="absolute left-1/2 top-3 -translate-x-1/2 flex items-center justify-center">
              <div className="h-3.5 w-3.5 rounded-full bg-slate-950 ring-2 ring-slate-800/80 flex items-center justify-center">
                <div className="h-1.5 w-1.5 rounded-full bg-blue-950/80" />
              </div>
            </div>

            {/* Status Icons */}
            <div className="flex items-center space-x-1.5 text-slate-300">
              <span className="text-[10px] font-mono tracking-tighter text-cyan-400 font-bold">5G</span>
              <Signal className="h-3.5 w-3.5" />
              <Wifi className="h-3.5 w-3.5" />
              <div className="flex items-center gap-0.5">
                <span className="text-[10px] font-mono">92%</span>
                <Battery className="h-3.5 w-3.5 text-emerald-400 fill-emerald-400" />
              </div>
            </div>
          </div>

          {/* Main App Content Viewport (Scrollable) */}
          <div className="relative flex-1 overflow-y-auto overflow-x-hidden scrollbar-none flex flex-col">
            {children}
          </div>

          {/* Android Navigation Bar */}
          <div className="relative z-30 flex items-center justify-around py-2.5 bg-slate-950/90 border-t border-slate-800/60 backdrop-blur-md">
            <button className="p-1 text-slate-500 hover:text-slate-200 transition-colors">
              <ArrowLeft className="h-4 w-4" />
            </button>
            <div className="h-1 w-24 rounded-full bg-slate-600/70" />
            <button className="p-1 text-slate-500 hover:text-slate-200 transition-colors">
              <Square className="h-3.5 w-3.5" />
            </button>
          </div>

        </div>
      </div>
    </div>
  );
};
