export type RiskLevel = 'safe' | 'low' | 'suspicious' | 'malicious';

export interface JunkFile {
  id: string;
  name: string;
  path: string;
  category: string;
  size: number; // in bytes
  ext: string;
  hashMd5: string;
  hashSha256: string;
  riskLevel: RiskLevel;
  threatDetails?: string;
  permissions?: string[];
  packageName?: string;
  timestamp: string;
  isSelected?: boolean;
}

export interface CategorySummary {
  name: string;
  count: number;
  size: number;
  description: string;
  iconName: string;
  badgeColor: string;
  files: JunkFile[];
  isCleaned?: boolean;
}

export interface ScanResult {
  status: 'success' | 'scanning' | 'idle' | 'error';
  total_files: number;
  total_bytes: number;
  categories: Record<string, CategorySummary>;
  scanTimestamp: number;
}

export interface CleanupLog {
  id: number;
  category: string;
  files_removed: number;
  bytes_freed: number;
  cleaned_at: string;
}

export interface CleanRule {
  id: number;
  rule_name: string;
  target_pattern: string;
  is_active: number;
  is_malicious: number; // 0 = standard cleanup, 1 = flagged malicious pattern/signature
  description?: string;
}

export interface OsintThreatCheckResponse {
  is_malicious: boolean;
  requires_confirmation: boolean;
  threat_name?: string;
  detection_ratio?: string;
  positives?: number;
  total_engines?: number;
  hash: string;
  hashType?: 'MD5' | 'SHA-1' | 'SHA-256' | 'UNKNOWN';
  fileName: string;
  category: string;
  details?: string;
  signatures?: string[];
  threat_score?: number; // 0-100 score
  community_reputation?: number;
  tags?: string[];
  suggestedRulePattern?: string;
  vendors?: {
    vendor: string;
    result: 'clean' | 'malicious' | 'suspicious' | 'undetected';
    signature?: string;
  }[];
}

export interface OsintReport {
  id: string;
  fileName: string;
  filePath: string;
  fileSizeBytes: number;
  md5: string;
  sha256: string;
  packageName?: string;
  targetSdk?: number;
  minSdk?: number;
  riskLevel: RiskLevel;
  detectionRatio: string; // e.g. "19/72 engines"
  threatVerdict: string;
  detectedSignatures: string[];
  permissions: {
    name: string;
    dangerLevel: 'normal' | 'dangerous' | 'signatureOrSystem';
    description: string;
  }[];
  entropy: number;
  isAdwareOrSpyware: boolean;
  recommendation: 'Safe to Delete' | 'Quarantine' | 'Immediate Purge' | 'Keep - Legitimate File';
}
