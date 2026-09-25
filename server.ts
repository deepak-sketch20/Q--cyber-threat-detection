import express from 'express';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { createServer as createViteServer } from 'vite';
import { analyzeSecurityText, SAMPLE_DATASETS } from './src/analyzerEngine';
import { executeEmailAlertProcess, getEmailConfig, generateReportFiles } from './src/emailService';
import {
  handleStreamingUpload,
  handleChunkInit,
  handleChunkUpload,
  handleChunkComplete,
  MAX_UPLOAD_SIZE,
  UPLOAD_CHUNK_SIZE,
  formatByteSize
} from './src/streamingUploadService';
import {
  simulateQubit,
  simulateBellState,
  simulateEntanglement,
  simulateTeleportation,
  applyPauliCorrection,
  simulateQuantumChannel,
  simulateCompleteQds,
  projectiveMeasurement
} from './src/qdsSimulatorEngine';
import {
  initializeDatabase,
  getAllCases,
  saveCase,
  getCaseById,
  deleteCase,
  getDatabaseStatus,
  setActiveEngine,
  getActiveEngine,
  testConnection,
  generateAnalystToken,
  verifyAnalystToken
} from './src/dbService';
import {
  createQdsPackage,
  cloneAndAttackPackage,
  QDS_PRESET_TEMPLATES,
  QdsAttackVectorId
} from './src/qdsPackageEngine';
import { verifyQdsPackage } from './src/qdsVerificationEngine';

async function startServer() {
  // Initialize persistent storage safely (PostgreSQL or resilient local fallback)
  await initializeDatabase();

  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // API 1: Sample List
  app.get('/api/samples', (req, res) => {
    const list = Object.entries(SAMPLE_DATASETS).map(([id, item]) => ({
      id,
      name: item.name,
      tag: item.tag
    }));
    res.json({ success: true, samples: list });
  });

  // API 2: Single Sample content
  app.get('/api/sample/:id', (req, res) => {
    const sample = SAMPLE_DATASETS[req.params.id];
    if (!sample) {
      return res.status(404).json({ success: false, error: 'Sample not found' });
    }
    res.json({ success: true, filename: req.params.id, content: sample.content });
  });

  // API 3: Streaming & Chunked File Upload (Supports up to 1 TB with incremental SHA-256)
  app.post('/api/upload', handleStreamingUpload);
  app.post('/api/upload/init', handleChunkInit);
  app.post('/api/upload/chunk', handleChunkUpload);
  app.post('/api/upload/complete', handleChunkComplete);
  app.get('/api/upload/config', (req, res) => {
    res.json({
      success: true,
      max_upload_size: MAX_UPLOAD_SIZE,
      chunk_size: UPLOAD_CHUNK_SIZE,
      max_upload_size_formatted: formatByteSize(MAX_UPLOAD_SIZE),
      chunk_size_formatted: formatByteSize(UPLOAD_CHUNK_SIZE)
    });
  });

  // API 4: Dispatch Email Alert Working Process (Live on-demand execution)
  app.post('/api/email/dispatch', async (req, res) => {
    try {
      const { summary, recipient, force_send } = req.body;
      if (!summary) {
        return res.status(400).json({ success: false, error: 'Forensic summary is required' });
      }
      const emailResult = await executeEmailAlertProcess(summary, recipient, force_send ?? true);
      res.json({ success: true, email_alert: emailResult });
    } catch (err: any) {
      console.error('API /api/email/dispatch error:', err);
      res.status(500).json({ success: false, error: err?.message || 'Email dispatch execution failed' });
    }
  });

  // API 5: Test Email Alert Trigger
  app.post('/api/email/test', async (req, res) => {
    try {
      const reqData = req.body || {};
      const caseId = reqData.case_id || `CASE-${Date.now().toString(36).toUpperCase()}`;
      const filename = reqData.filename || 'security_audit_test.pdf';
      const riskLevel = reqData.risk_level || 'HIGH';
      const threatScore = reqData.threat_score ?? 78;
      const sha256 = reqData.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const recipient = reqData.recipient || reqData.email || undefined;

      const mockSummary = {
        case_id: caseId,
        date_time: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
        target_file: filename,
        sha256,
        overall_status: 'THREAT DETECTED',
        risk_level: riskLevel,
        threat_score: threatScore,
        threat_indicators: [
          'Digital signature verification failed (INVALID_HASH_MISMATCH)',
          'Timestamp freshness expired (>120s delta)',
          'Elevated Quantum Bit Error Rate: QBER=14.20% (Threshold: 5.0%)',
          'Simulated Eavesdropping probability exceeded critical bounds (68.5%)'
        ],
        digital_signature_status: 'INVALID',
        file_integrity: 'MODIFIED',
        quantum_metrics: {
          qber: '14.20%',
          mismatch_rate: '14.20%',
          matching_rate: '85.80%',
          eavesdrop_probability: '68.50%',
          quantum_risk: 'HIGH (Simulated)',
          security_level: 'SUSPICIOUS (Simulated)'
        },
        timestamp_freshness: 'STALE',
        forensic_findings: `Simulated forensic diagnostic test for target '${filename}'. Triggered 4 rule-based threat indicators with threat score ${threatScore}/100 (${riskLevel}).`,
        recommended_action: '1. Quarantine target file.\n2. Revoke associated signing key certificate.\n3. Record SHA-256 in immutable incident ledger.',
        evidence: [
          `SHA-256: ${sha256}`,
          `Calculated Threat Score: ${threatScore}/100`,
          `Risk Level: ${riskLevel}`,
          `Simulated QBER: 14.20%`
        ]
      };

      const emailResult = await executeEmailAlertProcess(mockSummary, recipient, true);
      res.json({ success: true, alert_result: emailResult, case_id: caseId });
    } catch (err: any) {
      console.error('API /api/email/test error:', err);
      res.status(500).json({ success: false, error: err?.message || 'Email test execution failed' });
    }
  });

  // API 6: Email Configuration Status
  app.get('/api/config/email', (req, res) => {
    const cfg = getEmailConfig();
    res.json({
      success: true,
      owner_email: cfg.ownerEmail,
      smtp_server: cfg.smtpServer,
      smtp_port: cfg.smtpPort,
      smtp_configured: cfg.hasCredentials,
      is_test_mode: cfg.isTestMode
    });
  });

  // API 7: Download Forensic Report
  app.get('/api/report/download/:caseId', (req, res) => {
    try {
      const caseId = req.params.caseId;
      const fmt = ((req.query.format as string) || 'pdf').toLowerCase();
      const cleanCaseId = caseId.replace(/[^A-Za-z0-9_-]/g, '_');
      const filename = `Executive_Forensic_Summary_${cleanCaseId}.${fmt}`;
      const reportsDir = path.join(process.cwd(), 'reports');
      const filePath = path.join(reportsDir, filename);

      if (!fs.existsSync(filePath)) {
        // Fallback to generating on the fly if not found
        const fallbackText = `EXECUTIVE FORENSIC SUMMARY REPORT\nCase ID: ${caseId}\nStatus: ARCHIVED / RECONSTRUCTED\nGenerated: ${new Date().toISOString()}\n`;
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', fmt === 'pdf' ? 'application/pdf' : 'text/plain');
        return res.send(fallbackText);
      }

      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', fmt === 'pdf' ? 'application/pdf' : 'text/plain');
      res.sendFile(filePath);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Report download failed' });
    }
  });

  // API 8: System Health Endpoint (with Database Telemetry)
  app.get('/api/health', (req, res) => {
    const dbStatus = getDatabaseStatus();
    res.json({
      status: 'ok',
      service: 'Quantum Digital Signature Security Analyzer',
      timestamp: new Date().toISOString(),
      quantum_engine: 'Simulation-Based Statevector (Qiskit Equivalent)',
      database: dbStatus
    });
  });

  // API 8e: Get Database Configuration & Provider Options
  const handleDatabaseStatus = (req: any, res: any) => {
    try {
      const dbStatus = getDatabaseStatus();
      res.json({ success: true, database: dbStatus });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Failed to fetch database configuration' });
    }
  };
  app.get('/api/database/config', handleDatabaseStatus);
  app.get('/api/database/status', handleDatabaseStatus);

  // API 8f: Switch Active Database Engine
  app.post('/api/database/switch', async (req, res) => {
    try {
      const { engine } = req.body || {};
      if (!engine || !['supabase_postgresql', 'postgresql', 'file_storage', 'auto'].includes(engine)) {
        return res.status(400).json({ success: false, error: 'Invalid database engine. Choose: supabase_postgresql, postgresql, or file_storage.' });
      }
      const updatedStatus = setActiveEngine(engine);
      res.json({ success: true, message: `Active database engine switched to: ${engine}`, database: updatedStatus });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Failed to switch active database' });
    }
  });

  // API 8g: Live Database Connection Test
  app.post('/api/database/test', async (req, res) => {
    try {
      const { engine } = req.body || {};
      const testResult = await testConnection(engine);
      res.json(testResult);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Database test failed' });
    }
  });

  // ============================================================================
  // PERSISTENT STORAGE & CASE MANAGEMENT APIS (/api/cases)
  // ============================================================================

  // API 8b: Get all saved cases
  app.get('/api/cases', async (req, res) => {
    try {
      const cases = await getAllCases();
      res.json({ success: true, count: cases.length, cases });
    } catch (err: any) {
      console.error('API /api/cases GET error:', err);
      res.status(500).json({ success: false, error: err?.message || 'Failed to retrieve cases' });
    }
  });

  // API 8c: Save / Update a case manually
  app.post('/api/cases', async (req, res) => {
    try {
      if (!req.body || (!req.body.file_name && !req.body.case_id)) {
        return res.status(400).json({ success: false, error: 'Valid case information required.' });
      }
      const saved = await saveCase(req.body);
      res.json({ success: true, case: saved });
    } catch (err: any) {
      console.error('API /api/cases POST error:', err);
      res.status(500).json({ success: false, error: err?.message || 'Failed to save case' });
    }
  });

  // API 8d: Get single case by Case ID
  app.get('/api/cases/:caseId', async (req, res) => {
    try {
      const c = await getCaseById(req.params.caseId);
      if (!c) {
        return res.status(404).json({ success: false, error: 'Case record not found' });
      }
      res.json({ success: true, case: c });
    } catch (err: any) {
      console.error('API /api/cases/:caseId error:', err);
      res.status(500).json({ success: false, error: err?.message || 'Failed to retrieve case' });
    }
  });

  // API 8e: Delete a case
  app.delete('/api/cases/:caseId', async (req, res) => {
    try {
      const success = await deleteCase(req.params.caseId);
      res.json({ success });
    } catch (err: any) {
      console.error('API /api/cases/:caseId DELETE error:', err);
      res.status(500).json({ success: false, error: err?.message || 'Failed to delete case' });
    }
  });

  // ============================================================================
  // FORENSIC AUDIT AUTHENTICATION APIS (/api/auth)
  // ============================================================================

  // API 8f: Get Current Authenticated Analyst Profile
  app.get('/api/auth/me', (req, res) => {
    const authHeader = req.headers.authorization;
    let decoded = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      decoded = verifyAnalystToken(token);
    }

    res.json({
      success: true,
      authenticated: true,
      user: {
        id: decoded?.id || 'usr-01',
        username: decoded?.username || 'alice',
        email: 'alice@quantum-vault.internal',
        name: 'Dr. Alice Vance',
        role: decoded?.role || 'Lead Cryptographic Analyst',
        institution: 'University Cybersecurity Research Laboratory'
      }
    });
  });

  // API 8g: Analyst Login
  app.post('/api/auth/login', (req, res) => {
    try {
      const { email, username } = req.body || {};
      const user = {
        id: 'usr-01',
        username: username || 'alice',
        role: 'Lead Cryptographic Analyst'
      };
      const token = generateAnalystToken(user);
      res.json({
        success: true,
        token,
        user: {
          ...user,
          email: email || 'alice@quantum-vault.internal',
          name: 'Dr. Alice Vance',
          institution: 'University Cybersecurity Research Laboratory'
        }
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Authentication failed' });
    }
  });

  // API 8h: Analyst Logout
  app.post('/api/auth/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
  });

  // ============================================================================
  // QUANTUM SECURITY LAB & QDS SIMULATOR API ENDPOINTS
  // ============================================================================

  // API 9: Qubit Simulation
  app.get('/api/qds/qubit', (req, res) => {
    try {
      const stateType = (req.query.state as string) || 'superposition';
      const theta = req.query.theta ? parseFloat(req.query.theta as string) : Math.PI / 2;
      const phi = req.query.phi ? parseFloat(req.query.phi as string) : 0.0;
      const shots = req.query.shots ? parseInt(req.query.shots as string, 10) : 1024;
      const result = simulateQubit(stateType, theta, phi, shots);
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Qubit simulation error' });
    }
  });

  // API 10: Bell State Generator
  app.get('/api/qds/bell', (req, res) => {
    try {
      const bellState = (req.query.bell_state as string) || 'Phi+';
      const shots = req.query.shots ? parseInt(req.query.shots as string, 10) : 1024;
      const result = simulateBellState(bellState, shots);
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Bell state simulation error' });
    }
  });

  // API 11: Entanglement Verification
  app.get('/api/qds/entanglement', (req, res) => {
    try {
      const shots = req.query.shots ? parseInt(req.query.shots as string, 10) : 1024;
      const noise = req.query.noise_level ? parseFloat(req.query.noise_level as string) : 0.003;
      const result = simulateEntanglement(shots, noise);
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Entanglement simulation error' });
    }
  });

  // API 12: Quantum Teleportation (Supports both GET and POST)
  const handleTeleportation = (req: any, res: any) => {
    try {
      const params = req.method === 'GET' ? req.query : req.body || {};
      const { message_state, custom_theta, shots } = params;
      const result = simulateTeleportation(
        message_state || 'superposition',
        custom_theta !== undefined ? parseFloat(custom_theta) : undefined,
        shots ? parseInt(shots, 10) : 1024
      );
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Teleportation simulation error' });
    }
  };
  app.get('/api/qds/teleportation', handleTeleportation);
  app.post('/api/qds/teleportation', handleTeleportation);

  // API 13: Pauli Correction Lookup (Supports both GET and POST)
  const handlePauli = (req: any, res: any) => {
    try {
      const params = req.method === 'GET' ? req.query : req.body || {};
      const bits = params.bits || params.correction || '00';
      const result = applyPauliCorrection(bits);
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Pauli correction error' });
    }
  };
  app.get('/api/qds/pauli', handlePauli);
  app.post('/api/qds/pauli', handlePauli);

  // API 14: Quantum Channel Security & Attacks (Supports both GET and POST)
  const handleChannel = (req: any, res: any) => {
    try {
      const params = req.method === 'GET' ? req.query : req.body || {};
      const mode = params.mode || (params.channel_noise ? 'EAVESDROPPING' : 'NORMAL');
      const totalBits = params.total_bits ? parseInt(params.total_bits, 10) : 1000;
      const disturbance = params.disturbance_level || params.channel_noise;
      const result = simulateQuantumChannel(
        mode,
        totalBits,
        disturbance !== undefined ? parseFloat(disturbance) : undefined
      );
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Channel simulation error' });
    }
  };
  app.get('/api/qds/channel', handleChannel);
  app.post('/api/qds/channel', handleChannel);

  // API 15: Complete End-to-End QDS Simulation (Supports both GET and POST)
  const handleSimulate = (req: any, res: any) => {
    try {
      const params = req.method === 'GET' ? req.query : req.body || {};
      const result = simulateCompleteQds(params);
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Complete QDS simulation error' });
    }
  };
  app.get('/api/qds/simulate', handleSimulate);
  app.post('/api/qds/simulate', handleSimulate);

  // ============================================================================
  // QDS SECURITY & VERIFICATION PLATFORM API ENDPOINTS
  // ============================================================================

  // API 16: QDS Signing Engine - Create .QDS Package
  app.post('/api/qds/sign', async (req, res) => {
    try {
      const { filename, content, algorithm, signerIdentity, signerEmail, signerRole, signerOrg, quantumProtocol } = req.body || {};
      if (!content) {
        return res.status(400).json({ success: false, error: 'File content payload is required for QDS signing.' });
      }
      const pkg = await createQdsPackage({
        filename: filename || 'document.txt',
        content,
        algorithm,
        signerIdentity,
        signerEmail,
        signerRole,
        signerOrg,
        quantumProtocol
      });
      res.json({ success: true, package: pkg });
    } catch (err: any) {
      console.error('API /api/qds/sign error:', err);
      res.status(500).json({ success: false, error: err?.message || 'QDS package signing failed' });
    }
  });

  // API 17: Central Verification Engine - Verify .QDS Package
  app.post('/api/qds/verify', async (req, res) => {
    try {
      const { package: pkg } = req.body || {};
      if (!pkg || !pkg.original_artifact || !pkg.cryptography) {
        return res.status(400).json({ success: false, error: 'Valid .QDS package object is required.' });
      }
      const verificationResult = await verifyQdsPackage(pkg);
      res.json({ success: true, verification: verificationResult });
    } catch (err: any) {
      console.error('API /api/qds/verify error:', err);
      res.status(500).json({ success: false, error: err?.message || 'QDS package verification failed' });
    }
  });

  // API 18: Attack Lab - Generate Isolated Attacked Copy
  app.post('/api/qds/attack', (req, res) => {
    try {
      const { package: originalPkg, vector_id } = req.body || {};
      if (!originalPkg || !vector_id) {
        return res.status(400).json({ success: false, error: 'Original .QDS package and vector_id are required.' });
      }
      const attackedCopy = cloneAndAttackPackage(originalPkg, vector_id as QdsAttackVectorId);
      res.json({
        success: true,
        original_package_id: originalPkg.package_id,
        attacked_copy: attackedCopy
      });
    } catch (err: any) {
      console.error('API /api/qds/attack error:', err);
      res.status(500).json({ success: false, error: err?.message || 'Attack simulation mutation failed' });
    }
  });

  // API 19: Get QDS Presets
  app.get('/api/qds/presets', (req, res) => {
    res.json({ success: true, presets: QDS_PRESET_TEMPLATES });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Quantum Digital Signature Security Analyzer running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
