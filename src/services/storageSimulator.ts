import { JunkFile, CategorySummary, ScanResult, CleanupLog, CleanRule, OsintReport, RiskLevel, OsintThreatCheckResponse } from '../types';

// Keys for localStorage persistence
const STORAGE_LOGS_KEY = 'droidclean_sqlite_logs_v1';
const STORAGE_RULES_KEY = 'droidclean_sqlite_rules_v1';
const STORAGE_STATS_KEY = 'droidclean_stats_v1';

// Seed default rules from schema.sql with is_malicious flag
const DEFAULT_RULES: CleanRule[] = [
  { id: 1, rule_name: 'Temporary Files', target_pattern: '*.tmp', is_active: 1, is_malicious: 0, description: 'Intermediate application state and cache artifacts' },
  { id: 2, rule_name: 'Log Files', target_pattern: '*.log', is_active: 1, is_malicious: 0, description: 'Crash dumps, debugging logs and telemetry caches' },
  { id: 3, rule_name: 'Cache Directory', target_pattern: 'cache/*', is_active: 1, is_malicious: 0, description: 'Webview disk cache, image Glide/Picasso buffers' },
  { id: 4, rule_name: 'Orphaned Downloads', target_pattern: 'downloads/*.part', is_active: 1, is_malicious: 0, description: 'Interrupted HTTP downloads and incomplete buffers' },
  { id: 5, rule_name: 'Thumbnail Cache', target_pattern: '.thumbnails/*', is_active: 1, is_malicious: 0, description: 'MediaStore generated preview thumbnails' },
  { id: 6, rule_name: 'Orphaned APKs & Sideloads', target_pattern: 'downloads/*.apk', is_active: 1, is_malicious: 1, description: 'Installer packages scanned with VirusTotal OSINT intelligence' },
  { id: 7, rule_name: 'Hidden Dropper Payloads', target_pattern: '*.dex.enc', is_active: 1, is_malicious: 1, description: 'Obfuscated secondary payloads flagged as malicious' },
  { id: 8, rule_name: 'SQLite Journals', target_pattern: '*-journal', is_active: 1, is_malicious: 0, description: 'Rollback journals from closed database transactions' },
];

// Initial mock logs to show realistic history if empty
const INITIAL_LOGS: CleanupLog[] = [
  { id: 1, category: 'App Cache', files_removed: 42, bytes_freed: 245 * 1024 * 1024, cleaned_at: '2026-09-24 16:42:10' },
  { id: 2, category: 'Thumbnail Cache', files_removed: 184, bytes_freed: 382 * 1024 * 1024, cleaned_at: '2026-09-24 16:42:15' },
  { id: 3, category: 'System Temp Files', files_removed: 68, bytes_freed: 112 * 1024 * 1024, cleaned_at: '2026-09-23 09:15:32' },
];

// Mock generator for realistic Android junk files
function generateMockJunkFiles(): Record<string, JunkFile[]> {
  return {
    'App Cache': [
      {
        id: 'ac-1',
        name: 'f_001928.tmp',
        path: '/data/user/0/com.android.chrome/cache/f_001928.tmp',
        category: 'App Cache',
        size: 48 * 1024 * 1024,
        ext: 'tmp',
        hashMd5: 'c4ca4238a0b923820dcc509a6f75849b',
        hashSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        riskLevel: 'safe',
        timestamp: '2026-09-25 08:14',
      },
      {
        id: 'ac-2',
        name: 'glide_cache_7b319.data',
        path: '/data/user/0/com.instagram.android/cache/image_manager_disk_cache/glide_cache_7b319.data',
        category: 'App Cache',
        size: 92 * 1024 * 1024,
        ext: 'data',
        hashMd5: '9b73463316694829352e800d9f4e4e9a',
        hashSha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        riskLevel: 'safe',
        timestamp: '2026-09-25 09:30',
      },
      {
        id: 'ac-3',
        name: 'track_stream_chunk_088.tmp',
        path: '/data/user/0/com.spotify.music/cache/storage/track_stream_chunk_088.tmp',
        category: 'App Cache',
        size: 64 * 1024 * 1024,
        ext: 'tmp',
        hashMd5: 'd41d8cd98f00b204e9800998ecf8427e',
        hashSha256: '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f508c36e82c',
        riskLevel: 'safe',
        timestamp: '2026-09-25 07:11',
      },
      {
        id: 'ac-4',
        name: 'webview_gpu_cache.bin',
        path: '/data/user/0/com.google.android.youtube/cache/webview_gpu_cache.bin',
        category: 'App Cache',
        size: 35 * 1024 * 1024,
        ext: 'bin',
        hashMd5: '68b329da9893e34099c7d8ad5cb9c940',
        hashSha256: 'fd5cb0d7208ff5793081e77cb7b74ba7cb9ba6f1b3c99e90098df24b17df8020',
        riskLevel: 'safe',
        timestamp: '2026-09-24 22:50',
      }
    ],
    'System Temp Files': [
      {
        id: 'st-1',
        name: 'tombstone_04.log',
        path: '/data/tombstones/tombstone_04.log',
        category: 'System Temp Files',
        size: 18 * 1024 * 1024,
        ext: 'log',
        hashMd5: 'fcea920f7412b5da7be0cf42b8c93759',
        hashSha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
        riskLevel: 'low',
        threatDetails: 'Kernel crash stack trace artifact',
        timestamp: '2026-09-24 14:02',
      },
      {
        id: 'st-2',
        name: 'dexopt_profiling.dump',
        path: '/data/dalvik-cache/profiles/dexopt_profiling.dump',
        category: 'System Temp Files',
        size: 44 * 1024 * 1024,
        ext: 'dump',
        hashMd5: '70a01235123951abcca6284618210abc',
        hashSha256: 'fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9',
        riskLevel: 'safe',
        timestamp: '2026-09-25 04:19',
      },
      {
        id: 'st-3',
        name: 'battery_stats_history.bin',
        path: '/data/system/batterystats-checkin.bin.tmp',
        category: 'System Temp Files',
        size: 26 * 1024 * 1024,
        ext: 'tmp',
        hashMd5: '8b1a9953c4611296a827abf8c47804d7',
        hashSha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
        riskLevel: 'safe',
        timestamp: '2026-09-25 01:05',
      },
      {
        id: 'st-4',
        name: 'dropbox_telemetry_20260925.log',
        path: '/data/system/dropbox/event_log_entry.log',
        category: 'System Temp Files',
        size: 32 * 1024 * 1024,
        ext: 'log',
        hashMd5: 'c9f0f895fb98ab9159f51fd0297e236d',
        hashSha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
        riskLevel: 'safe',
        timestamp: '2026-09-25 05:40',
      }
    ],
    'Orphaned APKs': [
      {
        id: 'apk-1',
        name: 'mod_game_unlimited_v4.2.apk',
        path: '/sdcard/Download/mod_game_unlimited_v4.2.apk',
        category: 'Orphaned APKs',
        size: 78 * 1024 * 1024,
        ext: 'apk',
        packageName: 'com.modded.clash.gems',
        hashMd5: 'd7a8fbb307d7809469ca9ab5d0fed30e',
        hashSha256: '3a52e07198e3b26c2e3612502efae8eb3595cfad7e1f4094a9a957d1976a26df',
        riskLevel: 'malicious',
        threatDetails: 'OSINT Threat Intel: Detected by 34/72 anti-virus scanners (Adware/Dropper.Android)',
        permissions: ['android.permission.MANAGE_EXTERNAL_STORAGE', 'android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.RECEIVE_BOOT_COMPLETED'],
        timestamp: '2026-09-22 18:30',
      },
      {
        id: 'apk-2',
        name: 'vlc_android_beta_build_1402.apk',
        path: '/sdcard/Download/vlc_android_beta_build_1402.apk',
        category: 'Orphaned APKs',
        size: 38 * 1024 * 1024,
        ext: 'apk',
        packageName: 'org.videolan.vlc',
        hashMd5: '1a79a4d60de6718e8e5b326e338ae533',
        hashSha256: '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        riskLevel: 'safe',
        threatDetails: 'Clean signature verified by VideoLAN Org (0/72 Detections)',
        permissions: ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.FOREGROUND_SERVICE'],
        timestamp: '2026-09-20 11:15',
      },
      {
        id: 'apk-3',
        name: 'cleaner_booster_speed_ultra.apk',
        path: '/sdcard/Download/cleaner_booster_speed_ultra.apk',
        category: 'Orphaned APKs',
        size: 19 * 1024 * 1024,
        ext: 'apk',
        packageName: 'com.turbo.boost.cleaner.fake',
        hashMd5: '4f8a1098bc61498b50284e1b85438814',
        hashSha256: '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',
        riskLevel: 'suspicious',
        threatDetails: 'OSINT Flag: Aggressive full-screen adware payload and unwanted data collection',
        permissions: ['android.permission.INTERNET', 'android.permission.ACCESS_FINE_LOCATION', 'android.permission.QUERY_ALL_PACKAGES'],
        timestamp: '2026-09-23 20:04',
      }
    ],
    'Thumbnail Cache': [
      {
        id: 'tc-1',
        name: '.thumbdata4--1967290299',
        path: '/sdcard/DCIM/.thumbnails/.thumbdata4--1967290299',
        category: 'Thumbnail Cache',
        size: 210 * 1024 * 1024,
        ext: 'thumbdata4',
        hashMd5: '9e3669d19b675bd57058fd4664205d2a',
        hashSha256: '11a681329606d96700f1469e3e782d275218d61741ca6c93be7839ad7de056fe',
        riskLevel: 'safe',
        timestamp: '2026-09-25 10:00',
      },
      {
        id: 'tc-2',
        name: 'gallery_preview_cache.blob',
        path: '/sdcard/Android/data/com.sec.android.gallery3d/cache/gallery_preview_cache.blob',
        category: 'Thumbnail Cache',
        size: 135 * 1024 * 1024,
        ext: 'blob',
        hashMd5: '52c7104b46294e77741ef0ab062e7f8e',
        hashSha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        riskLevel: 'safe',
        timestamp: '2026-09-24 19:12',
      },
      {
        id: 'tc-3',
        name: 'video_keyframes.index',
        path: '/sdcard/DCIM/.thumbnails/video_keyframes.index',
        category: 'Thumbnail Cache',
        size: 55 * 1024 * 1024,
        ext: 'index',
        hashMd5: '099ebea48ea9666a7da21770b83d9251',
        hashSha256: 'b45cffe084dd3d20d928bee85e7b0f21422736b4e7492c696e95c1c05d7f1d43',
        riskLevel: 'safe',
        timestamp: '2026-09-25 02:44',
      }
    ],
    'Orphaned Downloads': [
      {
        id: 'od-1',
        name: 'ubuntu_touch_port.iso.part',
        path: '/sdcard/Download/ubuntu_touch_port.iso.part',
        category: 'Orphaned Downloads',
        size: 145 * 1024 * 1024,
        ext: 'part',
        hashMd5: '3593b4ffae2066fa286bb9f0d0e65306',
        hashSha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        riskLevel: 'safe',
        timestamp: '2026-09-21 15:20',
      },
      {
        id: 'od-2',
        name: 'podcast_episode_412.mp3.crdownload',
        path: '/sdcard/Download/podcast_episode_412.mp3.crdownload',
        category: 'Orphaned Downloads',
        size: 42 * 1024 * 1024,
        ext: 'crdownload',
        hashMd5: 'e1671797c52e15f763380b45e841ec32',
        hashSha256: '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
        riskLevel: 'safe',
        timestamp: '2026-09-23 12:00',
      }
    ]
  };
}

class StorageEngine {
  private currentFiles: Record<string, JunkFile[]> = generateMockJunkFiles();
  private logs: CleanupLog[] = [];
  private rules: CleanRule[] = [];

  constructor() {
    this.loadState();
  }

  private loadState() {
    if (typeof window === 'undefined') return;
    try {
      const savedLogs = localStorage.getItem(STORAGE_LOGS_KEY);
      this.logs = savedLogs ? JSON.parse(savedLogs) : INITIAL_LOGS;

      const savedRules = localStorage.getItem(STORAGE_RULES_KEY);
      this.rules = savedRules ? JSON.parse(savedRules) : DEFAULT_RULES;
    } catch {
      this.logs = INITIAL_LOGS;
      this.rules = DEFAULT_RULES;
    }
  }

  private saveState() {
    if (typeof window === 'undefined') return;
    try {
      localStorage.setItem(STORAGE_LOGS_KEY, JSON.stringify(this.logs));
      localStorage.setItem(STORAGE_RULES_KEY, JSON.stringify(this.rules));
    } catch (e) {
      console.warn('Storage save failed:', e);
    }
  }

  public getRules(): CleanRule[] {
    return [...this.rules];
  }

  public addRule(rule_name: string, target_pattern: string, is_malicious: number = 0, description?: string): CleanRule {
    const newId = this.rules.length > 0 ? Math.max(...this.rules.map(r => r.id)) + 1 : 1;
    const rule: CleanRule = {
      id: newId,
      rule_name,
      target_pattern,
      is_active: 1,
      is_malicious: is_malicious ? 1 : 0,
      description: description || `Clean rule for ${target_pattern}`
    };
    this.rules.push(rule);
    this.saveState();
    return rule;
  }

  public toggleRule(id: number): boolean {
    const r = this.rules.find(rule => rule.id === id);
    if (r) {
      r.is_active = r.is_active === 1 ? 0 : 1;
      this.saveState();
      return true;
    }
    return false;
  }

  public toggleRuleMalicious(id: number): boolean {
    const r = this.rules.find(rule => rule.id === id);
    if (r) {
      r.is_malicious = r.is_malicious === 1 ? 0 : 1;
      this.saveState();
      return true;
    }
    return false;
  }

  public deleteRule(id: number): boolean {
    const prevLen = this.rules.length;
    this.rules = this.rules.filter(rule => rule.id !== id);
    this.saveState();
    return this.rules.length < prevLen;
  }

  // OSINT VirusTotal API hash verification
  public async checkFileThreat(rawHash: string, fileName?: string): Promise<OsintThreatCheckResponse> {
    const fileHash = rawHash.trim().toLowerCase();
    
    // Detect Hash Type
    let hashType: 'MD5' | 'SHA-1' | 'SHA-256' | 'UNKNOWN' = 'UNKNOWN';
    if (/^[a-f0-9]{32}$/i.test(fileHash)) {
      hashType = 'MD5';
    } else if (/^[a-f0-9]{40}$/i.test(fileHash)) {
      hashType = 'SHA-1';
    } else if (/^[a-f0-9]{64}$/i.test(fileHash)) {
      hashType = 'SHA-256';
    }

    // Simulated VirusTotal v3 REST API lookup latency
    await new Promise(r => setTimeout(r, 550));

    // Curated known threat signatures
    const knownThreats: Record<string, Partial<OsintThreatCheckResponse>> = {
      '3a52e07198e3b26c2e3612502efae8eb3595cfad7e1f4094a9a957d1976a26df': {
        is_malicious: true,
        threat_name: 'Adware.AndroidOS.HiddenAds.gen / Dropper',
        detection_ratio: '34/72 engines',
        positives: 34,
        total_engines: 72,
        threat_score: 84,
        community_reputation: -68,
        tags: ['apk', 'android', 'dropper', 'hidden-ads', 'manage-external-storage', 'obfuscated'],
        suggestedRulePattern: 'downloads/*.apk',
        details: 'High-risk dropper containing stealth APK installer, full storage access bypass, and aggressive background ad dispatchers.',
        signatures: ['android.permission.MANAGE_EXTERNAL_STORAGE', 'android.permission.SYSTEM_ALERT_WINDOW', 'AUTO_BOOT_PERSISTENCE', 'Encrypted Payload in /assets/pkg.dex'],
        vendors: [
          { vendor: 'Kaspersky', result: 'malicious', signature: 'Trojan.AndroidOS.HiddenAds.ad' },
          { vendor: 'CrowdStrike Falcon', result: 'malicious', signature: 'Malicious_Confidence_98%' },
          { vendor: 'Sophos', result: 'malicious', signature: 'Andr/Dropr-A' },
          { vendor: 'Microsoft Defender', result: 'malicious', signature: 'Trojan:AndroidOS/Multiver.A' },
          { vendor: 'Bitdefender Mobile', result: 'malicious', signature: 'Android.Trojan.HiddenAds.B' },
          { vendor: 'ESET-NOD32', result: 'malicious', signature: 'Android/AdDisplay.HiddenAds' },
          { vendor: 'Avast Mobile', result: 'malicious', signature: 'Android:Dropper-CK [Trj]' },
          { vendor: 'Symantec', result: 'clean', signature: 'Undetected' },
          { vendor: 'Google Play Protect', result: 'malicious', signature: 'Blocked (Harmful App)' },
        ]
      },
      'd7a8fbb307d7809469ca9ab5d0fed30e': {
        is_malicious: true,
        threat_name: 'Adware.AndroidOS.HiddenAds.gen / Dropper',
        detection_ratio: '34/72 engines',
        positives: 34,
        total_engines: 72,
        threat_score: 84,
        community_reputation: -68,
        tags: ['apk', 'android', 'dropper', 'hidden-ads'],
        suggestedRulePattern: 'downloads/*.apk',
        details: 'MD5 representation of high-risk dropper containing stealth APK installer.',
        signatures: ['android.permission.MANAGE_EXTERNAL_STORAGE', 'android.permission.SYSTEM_ALERT_WINDOW'],
        vendors: [
          { vendor: 'Kaspersky', result: 'malicious', signature: 'Trojan.AndroidOS.HiddenAds' },
          { vendor: 'CrowdStrike', result: 'malicious', signature: 'Malicious_Dropper' },
          { vendor: 'Sophos', result: 'malicious', signature: 'Andr/Dropr-A' },
          { vendor: 'Microsoft', result: 'malicious', signature: 'Trojan:AndroidOS/Multiver.A' },
        ]
      },
      '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918': {
        is_malicious: true,
        threat_name: 'PUA:AndroidOS/FakeBooster.B (Potentially Unwanted Application)',
        detection_ratio: '14/72 engines',
        positives: 14,
        total_engines: 72,
        threat_score: 42,
        community_reputation: -25,
        tags: ['apk', 'pua', 'fake-booster', 'telemetry-beacon', 'query-all-packages'],
        suggestedRulePattern: '*booster*.apk',
        details: 'Intrusive advertising framework querying all installed packages, injecting mock memory cleaners, and displaying full-screen interstitials.',
        signatures: ['android.permission.QUERY_ALL_PACKAGES', 'INTRUSIVE_INTERSTITIAL_ADS', 'HEURISTIC_FAKE_RAM_BOOST'],
        vendors: [
          { vendor: 'Microsoft Defender', result: 'suspicious', signature: 'PUA:AndroidOS/FakeBooster.B' },
          { vendor: 'Malwarebytes', result: 'malicious', signature: 'Adware.Android.FakeSpeed' },
          { vendor: 'Kaspersky', result: 'suspicious', signature: 'not-a-virus:HEUR:AdWare.AndroidOS' },
          { vendor: 'Sophos', result: 'suspicious', signature: 'Generic PUA' },
          { vendor: 'Bitdefender', result: 'clean', signature: 'Undetected' },
          { vendor: 'CrowdStrike', result: 'clean', signature: 'Undetected' },
        ]
      },
      '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b': {
        is_malicious: false,
        threat_name: 'Clean & Verified (VideoLAN cryptographic signature)',
        detection_ratio: '0/72 engines',
        positives: 0,
        total_engines: 72,
        threat_score: 0,
        community_reputation: 92,
        tags: ['apk', 'media-player', 'open-source', 'videolan', 'signed-release'],
        details: 'Cryptographically verified release of VideoLAN open-source VLC player for Android. No threats detected.',
        signatures: ['Official Keystore Signature: SHA256withRSA', 'Valid Android Developers Certificate'],
        vendors: [
          { vendor: 'Kaspersky', result: 'clean', signature: 'Clean' },
          { vendor: 'CrowdStrike', result: 'clean', signature: 'Clean' },
          { vendor: 'Microsoft Defender', result: 'clean', signature: 'Clean' },
          { vendor: 'Sophos', result: 'clean', signature: 'Clean' },
          { vendor: 'Bitdefender', result: 'clean', signature: 'Clean' },
        ]
      },
    };

    if (knownThreats[fileHash]) {
      const match = knownThreats[fileHash];
      return {
        is_malicious: Boolean(match.is_malicious),
        requires_confirmation: Boolean(match.is_malicious),
        threat_name: match.threat_name,
        detection_ratio: match.detection_ratio,
        positives: match.positives,
        total_engines: match.total_engines,
        threat_score: match.threat_score ?? 0,
        community_reputation: match.community_reputation ?? 0,
        tags: match.tags ?? ['apk', 'android'],
        suggestedRulePattern: match.suggestedRulePattern,
        hash: fileHash,
        hashType,
        fileName: fileName || (match.is_malicious ? 'suspect_payload.apk' : 'verified_app.apk'),
        category: match.is_malicious ? 'Orphaned APKs' : 'Verified Safe',
        details: match.details,
        signatures: match.signatures,
        vendors: match.vendors,
      };
    }

    // Dynamic heuristic simulation for any user-pasted arbitrary hash:
    // We derive a deterministic result from the hash string so the same hash always yields the same result!
    let charSum = 0;
    for (let i = 0; i < fileHash.length; i++) {
      charSum += fileHash.charCodeAt(i);
    }

    const isSimulatedMalicious = (charSum % 4 === 0) || fileHash.includes('bad') || fileHash.includes('trojan') || fileHash.includes('virus');
    const isSimulatedSuspicious = !isSimulatedMalicious && (charSum % 3 === 0);

    if (isSimulatedMalicious) {
      const positives = 28 + (charSum % 25);
      return {
        is_malicious: true,
        requires_confirmation: true,
        threat_name: 'Trojan.AndroidOS.Agent.CustomQuery',
        detection_ratio: `${positives}/72 engines`,
        positives,
        total_engines: 72,
        threat_score: Math.min(95, positives * 2 + 10),
        community_reputation: -55,
        tags: ['apk', 'custom-hash', 'simulated-database', 'trojan-agent'],
        suggestedRulePattern: `*.${hashType.toLowerCase()}`,
        hash: fileHash,
        hashType,
        fileName: fileName || `flagged_binary_${fileHash.substring(0, 6)}.${hashType === 'UNKNOWN' ? 'bin' : 'apk'}`,
        category: 'Malware Database Match',
        details: 'Simulated VirusTotal threat database correlation: Match found in threat telemetry feed for mobile dropper payloads.',
        signatures: ['Simulated C2 beacon heuristic', 'Elevated permissions requested', 'Packed DEX payload'],
        vendors: [
          { vendor: 'Kaspersky', result: 'malicious', signature: 'Trojan.AndroidOS.Generic' },
          { vendor: 'CrowdStrike', result: 'malicious', signature: 'Malicious_Heuristic_92%' },
          { vendor: 'Microsoft Defender', result: 'malicious', signature: 'Trojan:AndroidOS/Agent' },
          { vendor: 'Sophos', result: 'malicious', signature: 'Andr/Agent-D' },
          { vendor: 'Bitdefender', result: 'suspicious', signature: 'Gen:Variant.Adware.Android' },
          { vendor: 'Symantec', result: 'clean', signature: 'Undetected' },
        ]
      };
    }

    if (isSimulatedSuspicious) {
      const positives = 7 + (charSum % 8);
      return {
        is_malicious: true,
        requires_confirmation: true,
        threat_name: 'Riskware:AndroidOS/UnwantedTool',
        detection_ratio: `${positives}/72 engines`,
        positives,
        total_engines: 72,
        threat_score: 35,
        community_reputation: -12,
        tags: ['riskware', 'ad-sdk', 'simulated-database'],
        suggestedRulePattern: `*${fileHash.substring(0, 4)}*`,
        hash: fileHash,
        hashType,
        fileName: fileName || `suspicious_module_${fileHash.substring(0, 6)}.dex`,
        category: 'Suspicious Artifact',
        details: 'Heuristic flagging: low-to-medium risk adware component or debug wrapper detected.',
        signatures: ['Excessive telemetry dispatch', 'Debug flags enabled'],
        vendors: [
          { vendor: 'Kaspersky', result: 'suspicious', signature: 'not-a-virus:HEUR:Riskware' },
          { vendor: 'Microsoft Defender', result: 'clean', signature: 'Clean' },
          { vendor: 'Sophos', result: 'suspicious', signature: 'Generic PUA' },
          { vendor: 'Bitdefender', result: 'clean', signature: 'Clean' },
        ]
      };
    }

    // Default clean response for arbitrary hash
    return {
      is_malicious: false,
      requires_confirmation: false,
      threat_name: 'Clean / Whitelisted (No threats identified)',
      detection_ratio: '0/72 engines',
      positives: 0,
      total_engines: 72,
      threat_score: 0,
      community_reputation: 65,
      tags: ['clean', 'whitelisted', 'safe'],
      hash: fileHash,
      hashType,
      fileName: fileName || `file_${fileHash.substring(0, 8)}.dat`,
      category: 'Verified Safe',
      details: 'File hash queried across 72 threat intelligence vendor feeds in the simulated VirusTotal database. No malicious behaviors detected.',
      vendors: [
        { vendor: 'Kaspersky', result: 'clean', signature: 'Clean' },
        { vendor: 'CrowdStrike', result: 'clean', signature: 'Clean' },
        { vendor: 'Microsoft Defender', result: 'clean', signature: 'Clean' },
        { vendor: 'Sophos', result: 'clean', signature: 'Clean' },
        { vendor: 'Bitdefender', result: 'clean', signature: 'Clean' },
        { vendor: 'ESET-NOD32', result: 'clean', signature: 'Clean' },
      ]
    };
  }

  public getLogs(): CleanupLog[] {
    return [...this.logs].sort((a, b) => new Date(b.cleaned_at).getTime() - new Date(a.cleaned_at).getTime());
  }

  public resetDemoData() {
    this.currentFiles = generateMockJunkFiles();
  }

  public getCurrentFiles(): Record<string, JunkFile[]> {
    return this.currentFiles;
  }

  // Scan simulation with detailed real progress stages
  public async runScan(
    onProgress?: (stage: string, percent: number) => void
  ): Promise<ScanResult> {
    const stages = [
      { text: 'Loading SQLite clean_rules & active glob patterns...', pct: 15 },
      { text: 'Scanning /data/user/0 sandbox app caches...', pct: 35 },
      { text: 'Traversing /sdcard MediaStore & .thumbnails...', pct: 60 },
      { text: 'Analyzing Orphaned APK headers & AndroidManifest...', pct: 80 },
      { text: 'Executing OSINT hash queries & threat heuristics...', pct: 95 },
      { text: 'Compiling storage diagnostic payload...', pct: 100 },
    ];

    for (const step of stages) {
      if (onProgress) onProgress(step.text, step.pct);
      await new Promise(r => setTimeout(r, 220));
    }

    // Filter categories based on active rules if applicable
    const activePatternRules = this.rules.filter(r => r.is_active === 1);
    const activePatterns = activePatternRules.map(r => r.target_pattern);

    const categories: Record<string, CategorySummary> = {};
    let totalFiles = 0;
    let totalBytes = 0;

    const meta: Record<string, { desc: string; icon: string; color: string }> = {
      'App Cache': { desc: 'Temporary webview, image and data buffers from installed apps', icon: 'Layers', color: '#38bdf8' },
      'System Temp Files': { desc: 'OS crash logs, tombstone dumps, dalvik profiling caches', icon: 'Cpu', color: '#a855f7' },
      'Orphaned APKs': { desc: 'Stale installer packages with OSINT security audit', icon: 'PackageCheck', color: '#f59e0b' },
      'Thumbnail Cache': { desc: 'High-res image gallery and video preview cache files', icon: 'Image', color: '#10b981' },
      'Orphaned Downloads': { desc: 'Unfinished file transfers, .part and .crdownload chunks', icon: 'DownloadCloud', color: '#ec4899' },
    };

    for (const [catName, fileList] of Object.entries(this.currentFiles)) {
      const size = fileList.reduce((acc, f) => acc + f.size, 0);
      const count = fileList.length;
      totalFiles += count;
      totalBytes += size;

      categories[catName] = {
        name: catName,
        count,
        size,
        description: meta[catName]?.desc || 'Targeted storage directory',
        iconName: meta[catName]?.icon || 'Folder',
        badgeColor: meta[catName]?.color || '#3b82f6',
        files: [...fileList],
        isCleaned: count === 0,
      };
    }

    return {
      status: 'success',
      total_files: totalFiles,
      total_bytes: totalBytes,
      categories,
      scanTimestamp: Date.now(),
    };
  }

  // Clean a specific category with OSINT threat check
  public async cleanCategory(
    categoryName: string,
    forceConfirmMalicious: boolean = false
  ): Promise<{
    status: 'success' | 'warning' | 'error';
    category: string;
    bytes_freed: number;
    files_removed: number;
    log?: CleanupLog;
    requires_confirmation?: boolean;
    threat_info?: OsintThreatCheckResponse;
    message?: string;
  }> {
    const files = this.currentFiles[categoryName] || [];
    if (files.length === 0) {
      return {
        status: 'success',
        category: categoryName,
        bytes_freed: 0,
        files_removed: 0,
        message: 'No files to clean in this category'
      };
    }

    // OSINT Threat Check: Check if category contains executables (.apk, .bin, .dex) or flagged malicious files
    if (!forceConfirmMalicious) {
      const maliciousFile = files.find(f => f.riskLevel === 'malicious' || f.riskLevel === 'suspicious' || f.ext === 'apk');
      if (maliciousFile) {
        const threatCheck = await this.checkFileThreat(maliciousFile.hashSha256 || maliciousFile.hashMd5, maliciousFile.name);
        if (threatCheck.is_malicious) {
          return {
            status: 'warning',
            category: categoryName,
            bytes_freed: 0,
            files_removed: 0,
            requires_confirmation: true,
            threat_info: threatCheck,
            message: `Security Warning: ${maliciousFile.name} was flagged by VirusTotal OSINT intelligence (${threatCheck.detection_ratio}). Explicit user confirmation required before deletion.`
          };
        }
      }
    }

    const count = files.length;
    const bytes = files.reduce((acc, f) => acc + f.size, 0);

    // Empty the files in this category
    this.currentFiles[categoryName] = [];

    // SQLite INSERT INTO cleanup_logs
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const newLogId = this.logs.length > 0 ? Math.max(...this.logs.map(l => l.id)) + 1 : 1;
    const logEntry: CleanupLog = {
      id: newLogId,
      category: categoryName,
      files_removed: count,
      bytes_freed: bytes,
      cleaned_at: nowStr,
    };

    this.logs.unshift(logEntry);
    this.saveState();

    return {
      status: 'success',
      category: categoryName,
      bytes_freed: bytes,
      files_removed: count,
      log: logEntry,
      message: `Successfully cleaned ${categoryName} (${(bytes / (1024 * 1024)).toFixed(1)} MB freed)`
    };
  }

  // Clean single file
  public deleteFile(fileId: string): { bytes_freed: number; category: string } | null {
    for (const [catName, fileList] of Object.entries(this.currentFiles)) {
      const idx = fileList.findIndex(f => f.id === fileId);
      if (idx !== -1) {
        const file = fileList[idx];
        fileList.splice(idx, 1);

        const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
        const newLogId = this.logs.length > 0 ? Math.max(...this.logs.map(l => l.id)) + 1 : 1;
        this.logs.unshift({
          id: newLogId,
          category: `${catName} (${file.name})`,
          files_removed: 1,
          bytes_freed: file.size,
          cleaned_at: nowStr,
        });
        this.saveState();

        return { bytes_freed: file.size, category: catName };
      }
    }
    return null;
  }

  // Clean all detected categories in one sweep
  public async cleanAll(): Promise<{ totalBytesFreed: number; totalFilesRemoved: number }> {
    let totalBytes = 0;
    let totalFiles = 0;
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);

    for (const [catName, fileList] of Object.entries(this.currentFiles)) {
      if (fileList.length > 0) {
        const catBytes = fileList.reduce((acc, f) => acc + f.size, 0);
        const catCount = fileList.length;
        totalBytes += catBytes;
        totalFiles += catCount;

        const newLogId = this.logs.length > 0 ? Math.max(...this.logs.map(l => l.id)) + 1 : 1;
        this.logs.unshift({
          id: newLogId,
          category: catName,
          files_removed: catCount,
          bytes_freed: catBytes,
          cleaned_at: nowStr,
        });

        this.currentFiles[catName] = [];
      }
    }

    this.saveState();
    return { totalBytesFreed: totalBytes, totalFilesRemoved: totalFiles };
  }

  // Run raw simulated SQL query
  public executeSql(sql: string): {
    success: boolean;
    columns?: string[];
    rows?: Record<string, unknown>[];
    message?: string;
    rowCount?: number;
  } {
    const trimmed = sql.trim();
    const upper = trimmed.toUpperCase();

    try {
      if (upper.startsWith('SELECT')) {
        if (upper.includes('FROM CLEANUP_LOGS')) {
          let rows = [...this.logs];
          if (upper.includes('ORDER BY CLEANED_AT DESC')) {
            rows.sort((a, b) => new Date(b.cleaned_at).getTime() - new Date(a.cleaned_at).getTime());
          }
          if (upper.includes('LIMIT')) {
            const match = trimmed.match(/LIMIT\s+(\d+)/i);
            if (match) {
              const lim = parseInt(match[1], 10);
              rows = rows.slice(0, lim);
            }
          }
          return {
            success: true,
            columns: ['id', 'category', 'files_removed', 'bytes_freed', 'cleaned_at'],
            rows: rows as unknown as Record<string, unknown>[],
            rowCount: rows.length,
          };
        } else if (upper.includes('FROM CLEAN_RULES')) {
          let rows = [...this.rules];
          if (upper.includes('WHERE IS_ACTIVE = 1')) {
            rows = rows.filter(r => r.is_active === 1);
          }
          return {
            success: true,
            columns: ['id', 'rule_name', 'target_pattern', 'is_active', 'is_malicious', 'description'],
            rows: rows as unknown as Record<string, unknown>[],
            rowCount: rows.length,
          };
        } else if (upper.includes('SUM(BYTES_FREED)')) {
          const sum = this.logs.reduce((a, b) => a + b.bytes_freed, 0);
          const count = this.logs.reduce((a, b) => a + b.files_removed, 0);
          return {
            success: true,
            columns: ['total_bytes_freed', 'total_files_removed', 'total_clean_sessions'],
            rows: [{ total_bytes_freed: sum, total_files_removed: count, total_clean_sessions: this.logs.length }],
            rowCount: 1,
          };
        } else {
          return {
            success: true,
            columns: ['info'],
            rows: [{ info: 'Query executed successfully. SQLite in-memory virtual adapter active.' }],
            rowCount: 1,
          };
        }
      } else if (upper.startsWith('INSERT INTO CLEAN_RULES')) {
        // Simple extraction
        const match = trimmed.match(/VALUES\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)/i);
        if (match) {
          const rule = this.addRule(match[1], match[2]);
          return {
            success: true,
            message: `1 row inserted into clean_rules (id: ${rule.id})`,
            rowCount: 1,
          };
        }
        return { success: false, message: 'Syntax error: use INSERT INTO clean_rules (rule_name, target_pattern) VALUES ("Name", "pattern")' };
      } else if (upper.startsWith('DELETE FROM CLEANUP_LOGS')) {
        const count = this.logs.length;
        this.logs = [];
        this.saveState();
        return { success: true, message: `${count} rows deleted from cleanup_logs`, rowCount: count };
      } else {
        return {
          success: true,
          message: `Query parsed and validated against SQLite 3.42 engine. Rows affected: 0`,
          rowCount: 0,
        };
      }
    } catch (err: unknown) {
      return { success: false, message: `SQL Error: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  // OSINT threat intelligence breakdown for suspicious files
  public getOsintReports(): OsintReport[] {
    return [
      {
        id: 'rep-1',
        fileName: 'mod_game_unlimited_v4.2.apk',
        filePath: '/sdcard/Download/mod_game_unlimited_v4.2.apk',
        fileSizeBytes: 78 * 1024 * 1024,
        md5: 'd7a8fbb307d7809469ca9ab5d0fed30e',
        sha256: '3a52e07198e3b26c2e3612502efae8eb3595cfad7e1f4094a9a957d1976a26df',
        packageName: 'com.modded.clash.gems',
        targetSdk: 33,
        minSdk: 21,
        riskLevel: 'malicious',
        detectionRatio: '34/72 engines',
        threatVerdict: 'Adware.AndroidOS.HiddenAds.gen / Dropper',
        detectedSignatures: [
          'Dangerous Scoped Storage Bypass (MANAGE_EXTERNAL_STORAGE)',
          'Background Service Auto-Start (RECEIVE_BOOT_COMPLETED)',
          'High Entropy Payload in assets/payload.dex (Obfuscated packer)',
          'Hardcoded C2 Command & Control endpoints detected',
        ],
        permissions: [
          { name: 'android.permission.MANAGE_EXTERNAL_STORAGE', dangerLevel: 'dangerous', description: 'Can read and write all files across entire device storage' },
          { name: 'android.permission.SYSTEM_ALERT_WINDOW', dangerLevel: 'dangerous', description: 'Can draw floating ads over other running apps' },
          { name: 'android.permission.RECEIVE_BOOT_COMPLETED', dangerLevel: 'normal', description: 'Automatically boots payload on phone power-on' },
          { name: 'android.permission.ACCESS_FINE_LOCATION', dangerLevel: 'dangerous', description: 'Accesses GPS location data for ad tracking' },
        ],
        entropy: 7.92,
        isAdwareOrSpyware: true,
        recommendation: 'Immediate Purge',
      },
      {
        id: 'rep-2',
        fileName: 'cleaner_booster_speed_ultra.apk',
        filePath: '/sdcard/Download/cleaner_booster_speed_ultra.apk',
        fileSizeBytes: 19 * 1024 * 1024,
        md5: '4f8a1098bc61498b50284e1b85438814',
        sha256: '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',
        packageName: 'com.turbo.boost.cleaner.fake',
        targetSdk: 31,
        minSdk: 24,
        riskLevel: 'suspicious',
        detectionRatio: '14/72 engines',
        threatVerdict: 'PUA:AndroidOS/FakeBooster.B',
        detectedSignatures: [
          'Fake RAM booster animation with aggressive full-screen interstitials',
          'Queries all installed packages (QUERY_ALL_PACKAGES)',
          'Excessive telemetry beacon to unknown offshore analytics servers',
        ],
        permissions: [
          { name: 'android.permission.QUERY_ALL_PACKAGES', dangerLevel: 'dangerous', description: 'Enumerates every app installed on user device' },
          { name: 'android.permission.INTERNET', dangerLevel: 'normal', description: 'Transmits collected device telemetry' },
          { name: 'android.permission.ACCESS_NETWORK_STATE', dangerLevel: 'normal', description: 'Checks connectivity' },
        ],
        entropy: 6.85,
        isAdwareOrSpyware: true,
        recommendation: 'Safe to Delete',
      },
      {
        id: 'rep-3',
        fileName: 'vlc_android_beta_build_1402.apk',
        filePath: '/sdcard/Download/vlc_android_beta_build_1402.apk',
        fileSizeBytes: 38 * 1024 * 1024,
        md5: '1a79a4d60de6718e8e5b326e338ae533',
        sha256: '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        packageName: 'org.videolan.vlc',
        targetSdk: 34,
        minSdk: 21,
        riskLevel: 'safe',
        detectionRatio: '0/72 engines',
        threatVerdict: 'Clean & Verified (VideoLAN cryptographic signature)',
        detectedSignatures: [
          'Official release keystore signature verified',
          'Standard open-source media player libraries (libvlc)',
        ],
        permissions: [
          { name: 'android.permission.READ_EXTERNAL_STORAGE', dangerLevel: 'dangerous', description: 'Reads local audio and video files for playback' },
          { name: 'android.permission.FOREGROUND_SERVICE', dangerLevel: 'normal', description: 'Maintains background audio playback notification' },
        ],
        entropy: 5.12,
        isAdwareOrSpyware: false,
        recommendation: 'Keep - Legitimate File',
      },
    ];
  }
}

export const storageEngine = new StorageEngine();
