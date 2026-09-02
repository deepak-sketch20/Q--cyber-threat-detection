import express from 'express';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import multer from 'multer';
import { createServer as createViteServer } from 'vite';
import { analyzeSecurityText, SAMPLE_DATASETS } from './src/analyzerEngine';
import { executeEmailAlertProcess, getEmailConfig, generateReportFiles } from './src/emailService';

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 16 * 1024 * 1024 } });

async function startServer() {
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

  // API 3: File Upload & Analysis
  app.post('/api/upload', upload.single('file'), async (req, res) => {
    try {
      let rawText = '';
      let filename = 'unknown.txt';
      let fileBytesLength = 0;
      let sha256Hash = '';
      const mode = (req.body.attack_mode as string) || 'Automatic Detection';

      if (req.file) {
        filename = req.file.originalname || 'uploaded_file.txt';
        fileBytesLength = req.file.buffer.length;
        sha256Hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
        rawText = req.file.buffer.toString('utf-8');
      } else if (req.body.sample_id && SAMPLE_DATASETS[req.body.sample_id]) {
        filename = req.body.sample_id;
        const content = SAMPLE_DATASETS[req.body.sample_id].content;
        rawText = content;
        fileBytesLength = Buffer.byteLength(content, 'utf-8');
        sha256Hash = crypto.createHash('sha256').update(content).digest('hex');
      } else if (req.body.text_content) {
        filename = (req.body.filename as string) || 'raw_text_payload.txt';
        rawText = req.body.text_content as string;
        fileBytesLength = Buffer.byteLength(rawText, 'utf-8');
        sha256Hash = crypto.createHash('sha256').update(rawText).digest('hex');
      } else {
        return res.status(400).json({ success: false, error: 'Please select a file first.' });
      }

      const refHash = (req.body.reference_hash as string) || undefined;
      const analysis = analyzeSecurityText(rawText, filename, fileBytesLength, sha256Hash, mode, refHash);

      // Execute Real Working Process for Email Alert if threat detected
      if (analysis.forensic_summary) {
        const emailResult = await executeEmailAlertProcess(
          analysis.forensic_summary,
          req.body.recipient || undefined,
          false
        );
        analysis.email_alert = emailResult;
        if (analysis.summary) {
          analysis.summary.email_dispatched = emailResult.triggered;
          analysis.summary.email_recipient = emailResult.recipient;
        }
      }

      res.json(analysis);
    } catch (err: any) {
      console.error('API /api/upload error:', err);
      res.status(500).json({ success: false, error: err?.message || 'Analysis internal failure' });
    }
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

  // Serve static assets from public & static folders
  app.use('/static', express.static(path.join(process.cwd(), 'static')));
  app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

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
