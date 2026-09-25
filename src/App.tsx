import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  FileCode,
  Lock,
  Mail,
  RefreshCw,
  Clock,
  Terminal,
  FileText,
  Activity,
  Layers,
  Database,
  Sun,
  Moon,
  Menu
} from 'lucide-react';
import { AnalysisResponse, SecurityLog, UploadProgressState, QdsPackage, QdsVerificationResult } from './types';
import { SAMPLE_DATASETS, analyzeSecurityText, computeSha256 } from './analyzerEngine';
import { DashboardView, HistoryCase } from './components/DashboardView';
import { AnalyzerView } from './components/AnalyzerView';
import { AttackSimulationView } from './components/AttackSimulationView';
import { QdsSigningEngineView } from './components/QdsSigningEngineView';
import { ReportView } from './components/ReportView';
import { AuditLogsView } from './components/AuditLogsView';
import { QuantumSecurityLab } from './components/QuantumSecurityLab';
import { CbomModal } from './components/CbomModal';
import { CertificateModal } from './components/CertificateModal';
import { ExecutiveForensicAlert } from './components/ExecutiveForensicAlert';
import { DatabaseModal } from './components/DatabaseModal';
import { LeftSidebar, NavTabId } from './components/LeftSidebar';
import { verifyQdsPackage } from './qdsVerificationEngine';
import { createQdsPackage, QDS_PRESET_TEMPLATES } from './qdsPackageEngine';

const MAX_UPLOAD_SIZE = 1024 * 1024 * 1024 * 1024; // 1 TB (1,099,511,627,776 bytes)

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 bytes';
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes < 1024 * 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  return `${(bytes / (1024 * 1024 * 1024 * 1024)).toFixed(2)} TB`;
}

export default function App() {
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [analysisState, setAnalysisState] = useState<'idle' | 'running' | 'completed' | 'error'>('idle');
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [currentOperation, setCurrentOperation] = useState<string>('Ready');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorDetails, setErrorDetails] = useState<string | null>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState<UploadProgressState | null>(null);
  const activeXhrRef = useRef<XMLHttpRequest | null>(null);
  const [activeSampleId, setActiveSampleId] = useState<string>('test_1_secure.txt');
  const [referenceHashInput, setReferenceHashInput] = useState<string>('');
  const [mode, setMode] = useState<string>('Automatic Detection');

  const [activeTab, setActiveTab] = useState<NavTabId>('dashboard');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState<boolean>(false);
  const [history, setHistory] = useState<HistoryCase[]>([]);
  const [filesAnalyzedCount, setFilesAnalyzedCount] = useState<number>(0);
  const [storageStatus, setStorageStatus] = useState<{ status: string; engine: string; message?: string }>({
    status: 'active',
    engine: 'Persistent Storage'
  });

  // QDS Security Package & Central Verification Engine State
  const [currentPackage, setCurrentPackage] = useState<QdsPackage | null>(null);
  const [qdsVerificationResult, setQdsVerificationResult] = useState<QdsVerificationResult | null>(null);

  // Initialize a baseline clean QDS Package on mount
  useEffect(() => {
    createQdsPackage({
      filename: QDS_PRESET_TEMPLATES[0].filename,
      content: QDS_PRESET_TEMPLATES[0].content,
      algorithm: 'ML-DSA-65 (Dilithium3)'
    }).then(pkg => {
      setCurrentPackage(pkg);
    });
  }, []);

  // Theme state: default to 'light' per user request, allow toggling
  const [theme, setTheme] = useState<'dark' | 'light'>('light');

  useEffect(() => {
    if (theme === 'light') {
      document.documentElement.classList.add('light');
      document.body.classList.add('light');
    } else {
      document.documentElement.classList.remove('light');
      document.body.classList.remove('light');
    }
    try {
      localStorage.setItem('qsecure_theme', theme);
    } catch {
      // Ignore if localStorage unavailable
    }
  }, [theme]);

  // Modals
  const [cbomOpen, setCbomOpen] = useState<boolean>(false);
  const [certModalOpen, setCertModalOpen] = useState<boolean>(false);
  const [emailAlertModalOpen, setEmailAlertModalOpen] = useState<boolean>(false);
  const [dbModalOpen, setDbModalOpen] = useState<boolean>(false);

  const [timeFormat, setTimeFormat] = useState<'local' | 'utc'>('local');
  const [currentTime, setCurrentTime] = useState<string>('');
  const [timezoneAbbr, setTimezoneAbbr] = useState<string>('');

  // Live real-time clock showing accurate local system time with UTC toggle
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      if (timeFormat === 'utc') {
        const utcStr = now.toISOString().replace('T', ' ').substring(0, 19);
        setCurrentTime(utcStr);
        setTimezoneAbbr('UTC');
      } else {
        const pad = (n: number) => String(n).padStart(2, '0');
        const year = now.getFullYear();
        const month = pad(now.getMonth() + 1);
        const day = pad(now.getDate());
        const hours = pad(now.getHours());
        const minutes = pad(now.getMinutes());
        const seconds = pad(now.getSeconds());
        setCurrentTime(`${year}-${month}-${day} ${hours}:${minutes}:${seconds}`);

        try {
          const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(now);
          const tz = parts.find(p => p.type === 'timeZoneName')?.value;
          setTimezoneAbbr(tz || 'Local');
        } catch {
          setTimezoneAbbr('Local');
        }
      }
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, [timeFormat]);

  // Fetch persistent cases & database telemetry from backend
  const loadSavedCases = async () => {
    try {
      const res = await fetch('/api/cases');
      if (res.ok) {
        const json = await res.json();
        if (json.success && Array.isArray(json.cases)) {
          setHistory(json.cases);
          setFilesAnalyzedCount(prev => Math.max(prev, json.cases.length));
        }
      }
    } catch (err) {
      console.warn('[Storage] Could not fetch saved cases from API:', err);
    }
  };

  const checkHealthAndStorage = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const health = await res.json();
        if (health.database) {
          setStorageStatus({
            status: health.database.status,
            engine: health.database.engine === 'supabase_postgresql'
              ? 'Supabase Cloud (PostgreSQL)'
              : health.database.engine === 'postgresql'
                ? 'PostgreSQL (Cloud)'
                : health.database.status === 'active_local_fallback'
                  ? 'Local File Storage (Fallback)'
                  : 'Local File Storage',
            message: health.database.message
          });
        }
      }
    } catch {
      // Fallback silently to client state
    }
  };

  // Initial load with baseline sample & persistent storage sync
  useEffect(() => {
    handleLoadSample('test_1_secure.txt');
    loadSavedCases();
    checkHealthAndStorage();
  }, []);

  // Centralized Analysis Execution Pipeline
  const runAnalysisPipeline = async (
    content: string | ArrayBuffer,
    fileName: string,
    fileSize: number,
    currentMode: string,
    refHash: string
  ) => {
    setLoading(true);
    setAnalysisState('running');
    setErrorMessage(null);
    setErrorDetails(null);
    setCurrentOperation('File received');
    setCurrentStepIndex(0);

    const startTime = performance.now();
    const timerInterval = setInterval(() => {
      setElapsedSeconds((performance.now() - startTime) / 1000);
    }, 50);

    try {
      // Step 0: Ingestion
      await new Promise(r => setTimeout(r, 60));

      // Step 1: Compute SHA-256 Digest
      setCurrentOperation('Calculating SHA-256 Digest...');
      setCurrentStepIndex(1);
      const hash = await computeSha256(content);
      await new Promise(r => setTimeout(r, 70));

      // Step 2: Signature verification
      setCurrentOperation('Verifying Cryptographic Signature...');
      setCurrentStepIndex(2);
      await new Promise(r => setTimeout(r, 70));

      // Step 3: Integrity analysis
      setCurrentOperation('Evaluating Message Integrity & Tampering Indicators...');
      setCurrentStepIndex(3);
      await new Promise(r => setTimeout(r, 70));

      // Step 4: Threat analysis
      setCurrentOperation('Correlating Threat Vectors & Multi-Factor Risk...');
      setCurrentStepIndex(4);
      await new Promise(r => setTimeout(r, 80));

      // Step 5: Quantum security simulation
      setCurrentOperation('Simulating Quantum Channel & Bell-State QBER...');
      setCurrentStepIndex(5);
      await new Promise(r => setTimeout(r, 80));

      // Step 6: Risk assessment
      setCurrentOperation('Compiling Risk Assessment & Audit Ledger...');
      setCurrentStepIndex(6);

      const rawText = typeof content === 'string' ? content : new TextDecoder('utf-8').decode(content);

      // Execute analysis (Server API with graceful local fallback)
      let analysisResult: AnalysisResponse;
      try {
        const formData = new FormData();
        const blob = typeof content === 'string'
          ? new Blob([content], { type: 'text/plain' })
          : new Blob([content]);
        formData.append('file', blob, fileName);
        formData.append('attack_mode', currentMode);
        if (refHash) formData.append('reference_hash', refHash);

        const res = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });

        if (res.ok) {
          analysisResult = await res.json();
        } else {
          analysisResult = analyzeSecurityText(rawText, fileName, fileSize, hash, currentMode, refHash);
        }
      } catch {
        analysisResult = analyzeSecurityText(rawText, fileName, fileSize, hash, currentMode, refHash);
      }

      setCurrentStepIndex(7);
      setCurrentOperation('Completed');
      setAnalysisState('completed');
      setData(analysisResult);

      // Update session history
      const riskScore = analysisResult.threat?.risk_score ?? 0;
      const isThreat = analysisResult.threat?.status === 'ATTACK DETECTED' || riskScore >= 60;
      const isSusp = !isThreat && (riskScore >= 35 || analysisResult.signature?.hash_mismatch);
      const statusStr = isThreat ? 'COMPROMISED' : isSusp ? 'SUSPICIOUS' : 'SECURE';

      setUploadProgress(prev => prev ? {
        ...prev,
        uploadPercent: 100,
        uploadedBytes: fileSize,
        totalBytes: fileSize,
        uploadStatus: 'completed',
        sha256Status: 'completed',
        analysisStatus: 'completed',
        calculatedHash: analysisResult.file?.sha256,
        finalVerdict: statusStr,
        riskScore
      } : null);

      const detectedCount = (analysisResult.attack_table || []).filter(
        r => r.status === 'AUTO-DETECTED' || r.status === 'SIMULATION' || r.status === 'ATTACK DETECTED'
      ).length;

      const historyEntry: HistoryCase = {
        case_id: analysisResult.case_id || `CASE-${Date.now().toString(36).toUpperCase()}`,
        file_name: fileName,
        timestamp: analysisResult.file?.upload_time || (() => {
          const d = new Date();
          const p = (n: number) => String(n).padStart(2, '0');
          return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
        })(),
        risk_score: riskScore,
        status: statusStr,
        threats_count: isThreat ? Math.max(1, detectedCount) : 0,
        primary_threat: analysisResult.threat?.detected_threat || 'None',
        data: analysisResult
      };

      setHistory(prev => [historyEntry, ...prev.filter(h => h.case_id !== historyEntry.case_id)].slice(0, 50));
      setFilesAnalyzedCount(prev => prev + 1);

      // Persist case record to backend database
      try {
        await fetch('/api/cases', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(historyEntry)
        });
      } catch (saveErr) {
        console.warn('[Storage] Case persistence sync error:', saveErr);
      }

    } catch (err: any) {
      console.error('Analysis pipeline error:', err);
      setAnalysisState('error');
      setErrorMessage('Unable to analyze the selected file.');
      setErrorDetails(err?.message || 'Verification engine encountered an error while processing the artifact.');
      setCurrentOperation('Failed');
    } finally {
      clearInterval(timerInterval);
      setLoading(false);
    }
  };

  const handleCancelUpload = () => {
    if (activeXhrRef.current) {
      activeXhrRef.current.abort();
      activeXhrRef.current = null;
    }
    setLoading(false);
    setAnalysisState('idle');
    setUploadProgress(prev => prev ? {
      ...prev,
      isUploading: false,
      uploadStatus: 'error',
      analysisStatus: 'error',
      error: 'Upload was cancelled by user.'
    } : null);
  };

  // QDS Platform Handlers: Central Verification, Package Signing, Attack Lab
  const handleVerifyPackage = async (pkg: QdsPackage) => {
    setLoading(true);
    setAnalysisState('running');
    setCurrentOperation('Executing Central Verification Engine (8-Layer Pipeline)...');
    setCurrentStepIndex(1);

    const verificationResult = await verifyQdsPackage(pkg);
    setQdsVerificationResult(verificationResult);
    setData(verificationResult.threat_analysis);
    setLoading(false);
    setAnalysisState('completed');
    setCurrentOperation('Completed');
    setCurrentStepIndex(7);

    const riskScore = verificationResult.risk_score;
    const isThreat = verificationResult.overall_decision === 'COMPROMISED';
    const isSusp = verificationResult.overall_decision === 'WARNING';
    const statusStr = isThreat ? 'COMPROMISED' : isSusp ? 'SUSPICIOUS' : 'SECURE';

    const historyEntry: HistoryCase = {
      case_id: verificationResult.threat_analysis.case_id || pkg.package_id,
      file_name: pkg.original_artifact.filename,
      timestamp: verificationResult.verified_at,
      risk_score: riskScore,
      status: statusStr,
      threats_count: verificationResult.failed_count,
      primary_threat: verificationResult.threat_analysis.summary.primary_threat,
      data: verificationResult.threat_analysis
    };

    setHistory(prev => [historyEntry, ...prev.filter(h => h.case_id !== historyEntry.case_id)].slice(0, 50));
    setFilesAnalyzedCount(prev => prev + 1);

    setActiveTab('analyzer');
  };

  const handlePackageGenerated = (pkg: QdsPackage) => {
    setCurrentPackage(pkg);
    setQdsVerificationResult(null);
  };

  const handleSendToAttackLab = (pkg: QdsPackage) => {
    setCurrentPackage(pkg);
    setActiveTab('attack-sim');
  };

  const handleLoadSample = async (sampleId: string, currentMode = mode, refHash = referenceHashInput) => {
    setSelectedFile(null);
    setActiveSampleId(sampleId);
    const sample = SAMPLE_DATASETS[sampleId];
    if (!sample) return;

    const fileBytes = new TextEncoder().encode(sample.content).length;
    setUploadProgress({
      isUploading: false,
      uploadPercent: 100,
      uploadedBytes: fileBytes,
      totalBytes: fileBytes,
      uploadStatus: 'completed',
      sha256Status: 'calculating',
      analysisStatus: 'running',
      fileName: sampleId,
      fileSizeFormatted: formatBytes(fileBytes)
    });

    await runAnalysisPipeline(sample.content, sampleId, fileBytes, currentMode, refHash);
  };

  const handleFileUpload = async (file: File, currentMode = mode, refHash = referenceHashInput) => {
    setSelectedFile(file);
    setActiveSampleId('');
    setErrorMessage(null);
    setErrorDetails(null);

    // 1. Client-Side Validation: Reject files > 1 TB
    if (file.size > MAX_UPLOAD_SIZE) {
      const formattedSize = formatBytes(file.size);
      const errMsg = 'File exceeds the maximum supported size of 1 TB.';
      setUploadProgress({
        isUploading: false,
        uploadPercent: 0,
        uploadedBytes: 0,
        totalBytes: file.size,
        uploadStatus: 'error',
        sha256Status: 'error',
        analysisStatus: 'error',
        fileName: file.name,
        fileSizeFormatted: formattedSize,
        error: errMsg
      });
      setErrorMessage(errMsg);
      setErrorDetails(`The selected file "${file.name}" is ${formattedSize}, which exceeds the system limit of 1 TB (1,099,511,627,776 bytes). Please select a file up to 1 TB.`);
      setAnalysisState('error');
      return;
    }

    // 2. Client-Side Validation: Reject dangerous executable binaries
    const ext = file.name.split('.').pop()?.toLowerCase() || '';
    const disallowedExtensions = ['exe', 'dll', 'so', 'dylib', 'sh', 'bat', 'cmd', 'msi', 'vbs', 'ps1', 'com', 'scr'];
    if (disallowedExtensions.includes(ext)) {
      const errMsg = 'File type not supported for digital signature analysis: Executable files cannot be uploaded.';
      setUploadProgress({
        isUploading: false,
        uploadPercent: 0,
        uploadedBytes: 0,
        totalBytes: file.size,
        uploadStatus: 'error',
        sha256Status: 'error',
        analysisStatus: 'error',
        fileName: file.name,
        fileSizeFormatted: formatBytes(file.size),
        error: errMsg
      });
      setErrorMessage('File type not supported.');
      setErrorDetails(`Files with extension .${ext} cannot be uploaded for cryptographic security verification.`);
      setAnalysisState('error');
      return;
    }

    // 3. Initialize Progress State (zero in-memory loading)
    setLoading(true);
    setAnalysisState('running');
    setCurrentStepIndex(0);
    setCurrentOperation('Uploading...');
    setElapsedSeconds(0);

    const startTime = performance.now();
    const timerInterval = setInterval(() => {
      setElapsedSeconds((performance.now() - startTime) / 1000);
    }, 50);

    setUploadProgress({
      isUploading: true,
      uploadPercent: 0,
      uploadedBytes: 0,
      totalBytes: file.size,
      uploadStatus: 'uploading',
      sha256Status: 'calculating',
      analysisStatus: 'waiting',
      fileName: file.name,
      fileSizeFormatted: formatBytes(file.size)
    });

    // 4. Stream upload via browser XMLHttpRequest (does NOT buffer into JS RAM)
    try {
      const formData = new FormData();
      formData.append('file', file, file.name);
      formData.append('attack_mode', currentMode);
      if (refHash) formData.append('reference_hash', refHash);

      const xhr = new XMLHttpRequest();
      activeXhrRef.current = xhr;

      xhr.open('POST', '/api/upload');

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && event.total > 0) {
          const percent = Math.min(99, Math.round((event.loaded / event.total) * 100));
          setUploadProgress(prev => prev ? {
            ...prev,
            uploadPercent: percent,
            uploadedBytes: event.loaded,
            totalBytes: event.total,
            uploadStatus: 'uploading',
            sha256Status: 'calculating',
            analysisStatus: 'waiting'
          } : null);
          setCurrentOperation(`Uploading... ${percent}%`);
        }
      };

      xhr.upload.onload = () => {
        setUploadProgress(prev => prev ? {
          ...prev,
          uploadPercent: 100,
          uploadedBytes: file.size,
          uploadStatus: 'completed',
          sha256Status: 'calculating',
          analysisStatus: 'running'
        } : null);
        setCurrentOperation('Upload completed. Starting security analysis...');
        setCurrentStepIndex(1);
      };

      xhr.onload = async () => {
        clearInterval(timerInterval);
        activeXhrRef.current = null;

        if (xhr.status === 200) {
          try {
            const analysisResult: AnalysisResponse = JSON.parse(xhr.responseText);
            const riskScore = analysisResult.threat?.risk_score ?? 0;
            const isThreat = analysisResult.threat?.status === 'ATTACK DETECTED' || riskScore >= 60;
            const isSusp = !isThreat && (riskScore >= 35 || analysisResult.signature?.hash_mismatch);
            const statusStr = isThreat ? 'COMPROMISED' : isSusp ? 'SUSPICIOUS' : 'SECURE';

            setUploadProgress(prev => prev ? {
              ...prev,
              uploadPercent: 100,
              uploadedBytes: file.size,
              uploadStatus: 'completed',
              sha256Status: 'completed',
              analysisStatus: 'completed',
              calculatedHash: analysisResult.file?.sha256,
              finalVerdict: statusStr,
              riskScore
            } : null);

            setCurrentStepIndex(7);
            setCurrentOperation('Completed');
            setAnalysisState('completed');
            setData(analysisResult);

            const detectedCount = (analysisResult.attack_table || []).filter(
              r => r.status === 'AUTO-DETECTED' || r.status === 'SIMULATION' || r.status === 'ATTACK DETECTED'
            ).length;

            const historyEntry: HistoryCase = {
              case_id: analysisResult.case_id || `CASE-${Date.now().toString(36).toUpperCase()}`,
              file_name: file.name,
              file_size: file.size,
              file_type: file.name.split('.').pop()?.toUpperCase() || 'BIN',
              sha256: analysisResult.file?.sha256 || '',
              user_id: 'usr-01',
              analysis_status: 'COMPLETED',
              security_status: statusStr,
              timestamp: analysisResult.file?.upload_time || new Date().toISOString().substring(11, 19),
              risk_score: riskScore,
              status: statusStr,
              threats_count: isThreat ? Math.max(1, detectedCount) : 0,
              primary_threat: analysisResult.threat?.detected_threat || 'None',
              data: analysisResult
            };

            setHistory(prev => [historyEntry, ...prev.filter(h => h.case_id !== historyEntry.case_id)].slice(0, 50));
            setFilesAnalyzedCount(prev => prev + 1);

            // Persist case record to backend database
            try {
              await fetch('/api/cases', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(historyEntry)
              });
            } catch (saveErr) {
              console.warn('[Storage] Case persistence sync error:', saveErr);
            }
          } catch (jsonErr: any) {
            setAnalysisState('error');
            setErrorMessage('Invalid response from security engine.');
            setErrorDetails(jsonErr?.message);
          }
        } else {
          let errStr = `Upload failed with HTTP ${xhr.status}`;
          try {
            const resObj = JSON.parse(xhr.responseText);
            if (resObj.error) errStr = resObj.error;
          } catch {}

          setUploadProgress(prev => prev ? {
            ...prev,
            uploadStatus: 'error',
            analysisStatus: 'error',
            error: errStr
          } : null);

          setAnalysisState('error');
          setErrorMessage(errStr.includes('exceeds') ? 'File exceeds the maximum supported size of 1 TB.' : 'Analysis failure.');
          setErrorDetails(errStr);
        }
        setLoading(false);
      };

      xhr.onerror = () => {
        clearInterval(timerInterval);
        activeXhrRef.current = null;
        setLoading(false);
        setAnalysisState('error');
        const err = 'Network connection failure during file upload. Please check your connection and retry.';
        setUploadProgress(prev => prev ? {
          ...prev,
          uploadStatus: 'error',
          analysisStatus: 'error',
          error: err
        } : null);
        setErrorMessage('Network connection failure.');
        setErrorDetails(err);
      };

      xhr.ontimeout = () => {
        clearInterval(timerInterval);
        activeXhrRef.current = null;
        setLoading(false);
        setAnalysisState('error');
        const err = 'Upload timed out. The file transfer took longer than allowed.';
        setUploadProgress(prev => prev ? {
          ...prev,
          uploadStatus: 'error',
          analysisStatus: 'error',
          error: err
        } : null);
        setErrorMessage('Upload timed out.');
        setErrorDetails(err);
      };

      xhr.onabort = () => {
        clearInterval(timerInterval);
        activeXhrRef.current = null;
        setLoading(false);
        setAnalysisState('idle');
      };

      xhr.send(formData);
    } catch (err: any) {
      clearInterval(timerInterval);
      setLoading(false);
      setAnalysisState('error');
      setErrorMessage('Could not initiate file upload.');
      setErrorDetails(err?.message || 'Unknown error');
    }
  };

  const handleModeChange = (newMode: string) => {
    setMode(newMode);
    if (selectedFile) {
      handleFileUpload(selectedFile, newMode);
    } else if (activeSampleId) {
      handleLoadSample(activeSampleId, newMode);
    } else if (data?.file?.filename && SAMPLE_DATASETS[data.file.filename]) {
      handleLoadSample(data.file.filename, newMode);
    }
  };

  const handleSelectCaseFromHistory = (caseData: AnalysisResponse) => {
    setData(caseData);
    setActiveTab('reports');
  };

  const handleRetry = () => {
    if (selectedFile) {
      handleFileUpload(selectedFile);
    } else if (activeSampleId) {
      handleLoadSample(activeSampleId);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setActiveSampleId('test_1_secure.txt');
    setReferenceHashInput('');
    setErrorMessage(null);
    setErrorDetails(null);
    handleLoadSample('test_1_secure.txt');
  };

  return (
    <div className={`min-h-screen w-full ${theme === 'light' ? 'bg-[#F8FAFC] text-[#0F172A]' : 'bg-[#0B0F19] text-[#F1F5F9]'} flex flex-col justify-between font-sans transition-colors duration-150 overflow-x-hidden`}>
      <div className="w-full flex-1 flex flex-col">
        {/* ===================================================================== */}
        {/* 1. APPLICATION SHELL: HEADER (Full Viewport Width) */}
        {/* ===================================================================== */}
        <header className={`w-full ${theme === 'light' ? 'bg-white border-b border-[#CBD5E1]' : 'bg-[#0E1526] border-b border-[#1E293B]'}`}>
          <div className="w-full px-4 sm:px-6 py-2.5">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <button
                  onClick={() => setMobileSidebarOpen(prev => !prev)}
                  className={`md:hidden p-1.5 rounded border transition-colors cursor-pointer ${
                    theme === 'light'
                      ? 'border-[#CBD5E1] bg-white text-[#0F172A] hover:bg-[#F1F5F9]'
                      : 'border-[#1E293B] bg-[#131B2E] text-[#F1F5F9] hover:bg-[#1E293B]'
                  }`}
                  aria-label="Toggle Navigation Menu"
                  title="Toggle Navigation Menu"
                >
                  <Menu className="w-4 h-4" />
                </button>
                <div className={`w-8 h-8 rounded flex items-center justify-center shrink-0 border ${
                  theme === 'light' ? 'bg-[#E0F2FE] border-[#BAE6FD]' : 'bg-[#0284C7]/15 border-[#0284C7]/30'
                }`}>
                  <Shield className={`w-4 h-4 ${theme === 'light' ? 'text-[#0284C7]' : 'text-[#38BDF8]'}`} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h1 className={`text-base sm:text-lg font-bold tracking-tight ${theme === 'light' ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                      Q-Secure
                    </h1>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold uppercase border ${
                      theme === 'light' ? 'bg-[#E0F2FE] border-[#BAE6FD] text-[#0284C7]' : 'bg-[#0284C7]/20 border-[#0284C7]/40 text-[#38BDF8]'
                    }`}>
                      SOC Defense Platform
                    </span>
                  </div>
                  <p className={`text-xs mt-0.5 ${theme === 'light' ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
                    Quantum Digital Signature Security Analyzer &bull; University Cybersecurity Research Laboratory
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <div className={`flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded border ${
                  theme === 'light'
                    ? 'bg-[#ECFDF5] border-[#A7F3D0] text-[#059669]'
                    : 'bg-[#064E3B]/30 border-[#065F46] text-[#34D399]'
                }`}>
                  <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-pulse"></span>
                  <span>System: Online</span>
                </div>
                <div
                  id="database-status-badge"
                  onClick={() => setDbModalOpen(true)}
                  className={`flex items-center gap-2 text-xs font-semibold px-2.5 py-1.5 rounded border cursor-pointer transition-all duration-150 group ${
                    theme === 'light'
                      ? 'bg-white border-[#CBD5E1] text-[#0F172A] hover:bg-[#F8FAFC] hover:border-[#0284C7]'
                      : 'bg-[#131B2E] border-[#1E293B] text-[#F1F5F9] hover:bg-[#1E293B] hover:border-[#0284C7] hover:text-[#38BDF8]'
                  }`}
                  title="Click to view and switch database provider"
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${storageStatus.status === 'connected' ? 'bg-[#10B981]' : (theme === 'light' ? 'bg-[#0284C7]' : 'bg-[#38BDF8]')} shrink-0`}></span>
                  <span className="flex items-center gap-1.5">
                    <span className={`font-normal ${theme === 'light' ? 'text-[#64748B] group-hover:text-[#0284C7]' : 'text-[#94A3B8] group-hover:text-[#38BDF8]'}`}>Database:</span>
                    <span className={`font-semibold ${theme === 'light' ? 'text-[#0F172A] group-hover:text-[#0284C7]' : 'text-[#F1F5F9] group-hover:text-[#38BDF8]'}`}>{storageStatus.engine}</span>
                    <span className={`ml-1 text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border transition-colors ${
                      theme === 'light'
                        ? 'bg-[#F1F5F9] text-[#0284C7] border-[#CBD5E1] font-bold group-hover:bg-[#E0F2FE] group-hover:border-[#38BDF8]'
                        : 'bg-[#1E293B] text-[#94A3B8] border-[#334155] group-hover:bg-[#0284C7]/20 group-hover:text-[#38BDF8] group-hover:border-[#0284C7]/40'
                    }`}>
                      Switch
                    </span>
                  </span>
                </div>
                <div
                  id="header-live-clock"
                  onClick={() => setTimeFormat(prev => prev === 'local' ? 'utc' : 'local')}
                  title={timeFormat === 'local' ? "Showing accurate Local System Time (Click to toggle UTC)" : "Showing UTC Time (Click to toggle Local)"}
                  className={`hidden sm:flex items-center gap-2 text-xs font-mono font-medium px-2.5 py-1.5 rounded border cursor-pointer transition-all duration-150 select-none group ${
                    theme === 'light'
                      ? 'bg-white border-[#CBD5E1] text-[#0F172A] hover:bg-[#F8FAFC] hover:border-[#0284C7]'
                      : 'bg-[#131B2E] border-[#1E293B] text-[#F1F5F9] hover:bg-[#1E293B] hover:border-[#0284C7] hover:text-[#38BDF8]'
                  }`}
                >
                  <Clock className={`w-3.5 h-3.5 shrink-0 ${theme === 'light' ? 'text-[#0284C7]' : 'text-[#38BDF8]'}`} />
                  <span className={`tabular-nums tracking-tight font-semibold ${theme === 'light' ? 'text-[#0F172A] group-hover:text-[#0284C7]' : 'text-[#F1F5F9] group-hover:text-[#38BDF8]'}`}>
                    {currentTime}
                  </span>
                  <span className={`text-[10px] font-sans font-semibold uppercase px-1.5 py-0.5 rounded border transition-colors ${
                    theme === 'light'
                      ? 'bg-[#F1F5F9] text-[#0284C7] border-[#CBD5E1] font-bold group-hover:bg-[#E0F2FE] group-hover:border-[#38BDF8]'
                      : 'bg-[#1E293B] text-[#94A3B8] border-[#334155] group-hover:bg-[#0284C7]/20 group-hover:text-[#38BDF8] group-hover:border-[#0284C7]/40'
                  }`}>
                    {timeFormat === 'local' ? (timezoneAbbr || 'Local') : 'UTC'}
                  </span>
                </div>

                {/* Light Mode / Dark Mode Switch Button */}
                <button
                  id="theme-mode-toggle"
                  onClick={() => setTheme(prev => prev === 'dark' ? 'light' : 'dark')}
                  role="switch"
                  aria-checked={theme === 'light'}
                  aria-label={theme === 'dark' ? "Switch to Light Mode" : "Switch to Dark Mode"}
                  title={theme === 'dark' ? "Switch to Light Mode" : "Switch to Dark Mode"}
                  className={`flex items-center gap-2 text-xs font-medium px-2.5 py-1.5 rounded border cursor-pointer transition-all duration-150 select-none group ${
                    theme === 'light'
                      ? 'bg-white border-[#CBD5E1] text-[#0F172A] hover:bg-[#F8FAFC] hover:border-[#0284C7]'
                      : 'bg-[#131B2E] border-[#1E293B] text-[#F1F5F9] hover:bg-[#1E293B] hover:border-[#0284C7] hover:text-[#38BDF8]'
                  }`}
                >
                  {theme === 'light' ? (
                    <>
                      <Sun className="w-3.5 h-3.5 text-[#D97706] transition-transform" />
                      <span className="font-semibold text-[#0F172A]">Light Mode</span>
                      <span className="w-7 h-3.5 rounded-full bg-[#0284C7] p-0.5 flex items-center justify-end transition-colors">
                        <span className="w-2.5 h-2.5 rounded-full bg-white shadow-xs transition-transform"></span>
                      </span>
                    </>
                  ) : (
                    <>
                      <Moon className="w-3.5 h-3.5 text-[#38BDF8] transition-transform" />
                      <span className="font-semibold text-[#F1F5F9]">Dark Mode</span>
                      <span className="w-7 h-3.5 rounded-full bg-[#1E293B] border border-[#334155] p-0.5 flex items-center transition-colors">
                        <span className="w-2.5 h-2.5 rounded-full bg-[#94A3B8] group-hover:bg-[#38BDF8] transition-transform"></span>
                      </span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Technical Sub-Header Strip */}
            <div className={`mt-2.5 pt-2 border-t text-[11px] font-mono flex flex-wrap items-center justify-between gap-x-3 gap-y-1 ${
              theme === 'light' ? 'border-[#E2E8F0] text-[#475569]' : 'border-[#1E293B] text-[#64748B]'
            }`}>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span>Prototype Version: <strong>1.0</strong></span>
                <span>&bull;</span>
                <span>Simulation Engine: <strong>Qiskit Aer</strong></span>
                <span>&bull;</span>
                <span>Hash Algorithm: <strong>SHA-256</strong></span>
                <span>&bull;</span>
                <span>Quantum Backend: <strong>Statevector Simulator</strong></span>
              </div>
              <div className="flex items-center gap-3">
                <span>Mode: <strong className={theme === 'light' ? 'text-[#0284C7]' : 'text-[#38BDF8]'}>{mode}</strong></span>
              </div>
            </div>
          </div>
        </header>

        {/* ===================================================================== */}
        {/* 2. APPLICATION LAYOUT: [ LEFT SIDEBAR 260px ] [ MAIN CONTENT ] */}
        {/* ===================================================================== */}
        <div className="flex flex-col md:flex-row w-full flex-1">
          {/* Left Sidebar (260px on desktop) */}
          <LeftSidebar
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            theme={theme}
            mobileOpen={mobileSidebarOpen}
            setMobileOpen={setMobileSidebarOpen}
            onOpenCbom={() => setCbomOpen(true)}
            onOpenCert={() => setCertModalOpen(true)}
            onOpenEmailAlert={() => setEmailAlertModalOpen(true)}
          />

          {/* Main Content Area (To the RIGHT of the sidebar, full available width) */}
          <div className="flex-1 min-w-0 flex flex-col w-full">
            {/* MAIN CONTENT VIEW CONTROLLER */}
            <main className="w-full px-4 sm:px-6 py-4 flex-1">
          {activeTab === 'dashboard' && (
            <DashboardView
              data={data}
              history={history}
              filesAnalyzedCount={filesAnalyzedCount}
              storageStatus={storageStatus}
              theme={theme}
              onRefreshCases={loadSavedCases}
              onSelectCase={handleSelectCaseFromHistory}
              onNavigateToAnalyzer={() => setActiveTab('analyzer')}
              onNavigateToReport={() => setActiveTab('reports')}
              onLoadSample={handleLoadSample}
              onFileUpload={handleFileUpload}
              loading={loading}
              analysisState={analysisState}
              uploadProgress={uploadProgress}
              onCancelUpload={handleCancelUpload}
              selectedFile={selectedFile}
              onRunAnalysis={() => {
                if (selectedFile) handleFileUpload(selectedFile);
                else if (activeSampleId) handleLoadSample(activeSampleId);
              }}
              activeSampleId={activeSampleId}
              mode={mode}
              onModeChange={handleModeChange}
              errorMessage={errorMessage}
              errorDetails={errorDetails}
              onDismissError={() => {
                setErrorMessage(null);
                setErrorDetails(null);
              }}
              onNavigateToSigning={() => setActiveTab('qds-signing')}
              onNavigateToAttackLab={() => setActiveTab('attack-sim')}
              activeQdsPackage={currentPackage}
              qdsVerificationResult={qdsVerificationResult}
            />
          )}

          {activeTab === 'qds-signing' && (
            <QdsSigningEngineView
              onPackageGenerated={handlePackageGenerated}
              onSendToVerify={handleVerifyPackage}
              onSendToAttackLab={handleSendToAttackLab}
              theme={theme}
            />
          )}

          {activeTab === 'analyzer' && (
            <AnalyzerView
              data={data}
              loading={loading}
              analysisState={analysisState}
              currentStepIndex={currentStepIndex}
              elapsedSeconds={elapsedSeconds}
              currentOperation={currentOperation}
              errorMessage={errorMessage}
              errorDetails={errorDetails}
              selectedFile={selectedFile}
              uploadProgress={uploadProgress}
              onCancelUpload={handleCancelUpload}
              mode={mode}
              referenceHashInput={referenceHashInput}
              onModeChange={handleModeChange}
              onReferenceHashChange={setReferenceHashInput}
              onFileUpload={handleFileUpload}
              onRunAnalysis={() => {
                if (selectedFile) handleFileUpload(selectedFile);
                else if (activeSampleId) handleLoadSample(activeSampleId);
              }}
              onReset={handleReset}
              onRetry={handleRetry}
              onDismissError={() => setErrorMessage(null)}
              onOpenCertModal={() => setCertModalOpen(true)}
              onOpenCbomModal={() => setCbomOpen(true)}
              qdsVerificationResult={qdsVerificationResult}
              activeQdsPackage={currentPackage}
              onNavigateToSigning={() => setActiveTab('qds-signing')}
              onNavigateToAttackLab={() => setActiveTab('attack-sim')}
              theme={theme}
            />
          )}

          {activeTab === 'attack-sim' && (
            <AttackSimulationView
              currentPackage={currentPackage}
              onVerifyPackage={handleVerifyPackage}
              theme={theme}
              onLoadAndAnalyze={(sampleId) => {
                handleLoadSample(sampleId);
                setActiveTab('analyzer');
              }}
            />
          )}

          {activeTab === 'quantum-lab' && (
            <QuantumSecurityLab />
          )}

          {activeTab === 'reports' && (
            <ReportView data={data} theme={theme} />
          )}

          {activeTab === 'audit-logs' && (
            <AuditLogsView logs={data?.logs || []} caseId={data?.case_id} />
          )}
        </main>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 5. MODALS & POPUPS */}
      {/* ===================================================================== */}
      <CbomModal
        cbom={data?.cbom}
        isOpen={cbomOpen}
        onClose={() => setCbomOpen(false)}
      />

      <CertificateModal
        cert={data?.certificate_analysis}
        isOpen={certModalOpen}
        onClose={() => setCertModalOpen(false)}
      />

      <ExecutiveForensicAlert
        data={data}
        alert={data?.email_alert}
        forensicSummary={data?.forensic_summary}
        isOpen={emailAlertModalOpen}
        onClose={() => setEmailAlertModalOpen(false)}
        defaultRecipient="deepakmurugaiyan@gmail.com"
        caseId={data?.case_id || 'CASE-PROTOTYPE'}
      />

      <DatabaseModal
        isOpen={dbModalOpen}
        onClose={() => setDbModalOpen(false)}
        currentEngine={storageStatus.engine}
        currentStatus={storageStatus.status}
        onDatabaseChanged={() => {
          checkHealthAndStorage();
          loadSavedCases();
        }}
      />

      {/* ===================================================================== */}
      {/* 6. ACADEMIC & INSTITUTIONAL FOOTER */}
      {/* ===================================================================== */}
      <footer className={`border-t mt-6 py-3.5 transition-colors ${
        theme === 'light' ? 'bg-[#F8FAFC] border-[#CBD5E1] text-[#475569]' : 'bg-[#0E1526] border-[#1E293B] text-[#64748B]'
      }`}>
        <div className="w-full px-4 sm:px-6 flex flex-col md:flex-row items-center justify-between gap-3 text-xs">
          <div>
            <div className={`font-semibold ${theme === 'light' ? 'text-[#0F172A]' : 'text-[#94A3B8]'}`}>
              University Cybersecurity Research Laboratory &bull; SOC Platform
            </div>
            <div className={`text-[11px] mt-0.5 ${theme === 'light' ? 'text-[#475569]' : 'text-[#64748B]'}`}>
              Quantum Digital Signature (QDS) Security Evaluation Platform &bull; Protocol Analysis &amp; Threat Detection
            </div>
          </div>

          <div className={`text-[11px] md:text-right font-mono ${theme === 'light' ? 'text-[#475569]' : 'text-[#64748B]'}`}>
            <div>Engine: Qiskit Statevector Simulator &bull; Digest: SHA-256</div>
            <div className="mt-0.5">
              Confidential Research Prototype &bull; Local Simulated Environment
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
