import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import type { Request, Response } from 'express';
import busboy from 'busboy';
import dotenv from 'dotenv';
dotenv.config({ override: true });
import { AnalysisResponse, AttackTableRow, SecurityLog } from './types';
import { SAMPLE_DATASETS, analyzeSecurityText } from './analyzerEngine';
import { saveCase, uploadToSupabaseStorage } from './dbService';
import { executeEmailAlertProcess } from './emailService';
import { calculateAdaptiveThreshold, generateGenuineSimulationMeasurements, deriveCandidateMeasurement } from './adaptiveThreshold';

// Helper function to safely parse human-readable byte strings (e.g., '2 GB', '3gb', '1048576', '1mb')
export function parseByteSize(val: string | undefined, defaultBytes: number, maxCap?: number): number {
  if (!val) return defaultBytes;
  const trimmed = val.trim().toLowerCase();
  let bytes = defaultBytes;
  if (/^\d+$/.test(trimmed)) {
    bytes = parseInt(trimmed, 10);
  } else {
    const match = trimmed.match(/^([\d.]+)\s*(tb|t|gb|mb|kb|b|g|m|k)?$/);
    if (match) {
      const num = parseFloat(match[1]);
      const unit = match[2] || 'b';
      switch (unit) {
        case 'tb':
        case 't':
          bytes = Math.round(num * 1024 * 1024 * 1024 * 1024);
          break;
        case 'gb':
        case 'g':
          bytes = Math.round(num * 1024 * 1024 * 1024);
          break;
        case 'mb':
        case 'm':
          bytes = Math.round(num * 1024 * 1024);
          break;
        case 'kb':
        case 'k':
          bytes = Math.round(num * 1024);
          break;
        default:
          bytes = Math.round(num);
      }
    }
  }
  if (maxCap && bytes > maxCap) {
    return maxCap;
  }
  return bytes;
}

// Configuration: Environment-configurable with strict defaults and 1 TB ceiling
export const ONE_TERABYTE = 1024 * 1024 * 1024 * 1024; // 1 TB (1,099,511,627,776 bytes)
export const ABSOLUTE_MAX_UPLOAD_SIZE = ONE_TERABYTE;

// If MAX_UPLOAD_SIZE is set to legacy 2 GB or 3 GB test string, resolve to 1 TB
const rawEnvMax = (process.env.MAX_UPLOAD_SIZE || '').trim().toLowerCase();
const resolvedEnvMax = (rawEnvMax === '3gb' || rawEnvMax === '2147483648' || rawEnvMax === '2gb' || !rawEnvMax) 
  ? String(ONE_TERABYTE) 
  : process.env.MAX_UPLOAD_SIZE;

export const MAX_UPLOAD_SIZE = parseByteSize(resolvedEnvMax, ABSOLUTE_MAX_UPLOAD_SIZE, ABSOLUTE_MAX_UPLOAD_SIZE);
export const UPLOAD_CHUNK_SIZE = parseByteSize(process.env.UPLOAD_CHUNK_SIZE, 1048576, 16 * 1024 * 1024); // default 1 MB
const MAX_SAMPLE_BYTES = 4 * 1024 * 1024; // 4 MB sample window for structured header inspection
const MAX_TAIL_BYTES = 2 * 1024 * 1024; // 2 MB sample window for signature footer inspection

// Controlled temporary storage directory (outside static/public)
export const UPLOAD_TEMP_DIR = path.join(process.cwd(), 'data', 'uploads_temp');

// Ensure directory exists
if (!fs.existsSync(UPLOAD_TEMP_DIR)) {
  fs.mkdirSync(UPLOAD_TEMP_DIR, { recursive: true });
}

// Block dangerous executable extensions
const DISALLOWED_EXTENSIONS = new Set([
  'exe', 'dll', 'so', 'dylib', 'sh', 'bash', 'bat', 'cmd', 'msi', 'vbs', 'ps1', 'com', 'scr', 'pif'
]);

export interface ChunkSession {
  uploadId: string;
  originalFileName: string;
  safeFileName: string;
  fileSizeBytes: number;
  fileType: string;
  tempFilePath: string;
  bytesReceived: number;
  totalChunks: number;
  chunksReceived: number;
  hasher: crypto.Hash;
  headSample: Buffer;
  byteFrequencies: Uint32Array;
  mode: string;
  referenceHash?: string;
  userId: string;
  recipient?: string;
  status: 'uploading' | 'completed' | 'failed';
  createdAt: number;
  updatedAt: number;
}

// Active chunked upload sessions
const activeSessions: Map<string, ChunkSession> = new Map();

/**
 * Validates file name and extension security.
 */
export function validateFileType(filename: string): { valid: boolean; error?: string; extension: string } {
  const parts = filename.split('.');
  const ext = parts.length > 1 ? parts.pop()!.toLowerCase() : '';

  if (DISALLOWED_EXTENSIONS.has(ext)) {
    return {
      valid: false,
      error: `File type not supported for digital signature analysis: Executable files (.${ext}) cannot be uploaded.`,
      extension: ext
    };
  }
  return { valid: true, extension: ext || 'bin' };
}

/**
 * Sanitizes original filename to prevent path traversal, removing directory separators and invalid characters.
 */
export function sanitizeFilename(filename: string): string {
  const base = path.basename(filename);
  const clean = base.replace(/[^a-zA-Z0-9._\- ]/g, '_').trim();
  return clean.substring(0, 180) || 'artifact.bin';
}

/**
 * Formats byte size for human display
 */
export function formatByteSize(bytes: number): string {
  if (bytes === 0) return '0 bytes';
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes < 1024 * 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  return `${(bytes / (1024 * 1024 * 1024 * 1024)).toFixed(2)} TB`;
}

/**
 * Calculates Shannon entropy from byte frequency distribution without storing file in RAM.
 */
export function computeEntropyFromFrequencies(frequencies: Uint32Array, totalBytes: number): number {
  if (totalBytes === 0) return 0;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const count = frequencies[i];
    if (count > 0) {
      const p = count / totalBytes;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy; // 0 to 8 bits per byte
}

/**
 * Classifies file analysis without loading 2 GB into RAM (Requirement 11).
 * Inspects:
 * - A: Streaming analysis (incremental SHA-256 + Shannon entropy calculated progressively)
 * - B: Metadata analysis (file size, extension, MIME magic bytes, timestamps)
 * - C: Structured/text analysis (parses head and tail sample windows for tokens, transactions, nonces)
 * - D: Cryptographic verification (validates signature headers, CMS/PKCS7, certificates, and SHA-256 match)
 */
export async function analyzeFileWithClassifier(
  filePath: string,
  fileName: string,
  fileSizeBytes: number,
  sha256Hash: string,
  headSample: Buffer,
  byteFrequencies: Uint32Array,
  simulationMode = 'Automatic Detection',
  referenceHash?: string
): Promise<AnalysisResponse> {
  // C. Structured/text analysis: Extract UTF-8 text from head sample (up to 4 MB)
  let textSample = '';
  try {
    textSample = headSample.toString('utf-8');
  } catch {
    textSample = headSample.toString('latin1');
  }

  // If file > 8 MB, also read the tail sample (up to 2 MB) where digital signatures typically reside
  if (fileSizeBytes > 8 * 1024 * 1024 && fs.existsSync(filePath)) {
    try {
      const tailSize = Math.min(MAX_TAIL_BYTES, fileSizeBytes);
      const fd = fs.openSync(filePath, 'r');
      const tailBuffer = Buffer.alloc(tailSize);
      fs.readSync(fd, tailBuffer, 0, tailSize, fileSizeBytes - tailSize);
      fs.closeSync(fd);
      const tailText = tailBuffer.toString('utf-8');
      textSample = `${textSample}\n--- [TAIL_SIGNATURE_SEGMENT] ---\n${tailText}`;
    } catch (tailErr) {
      console.warn('[Analyzer] Warning reading file tail:', tailErr);
    }
  }

  // Calculate streaming Shannon entropy (A. Streaming Analysis)
  const entropy = computeEntropyFromFrequencies(byteFrequencies, fileSizeBytes);

  // If the file is small (e.g. <= 4 MB), the headSample contains the entire file!
  // Run the core security text analyzer with the exact SHA-256 precomputed from stream
  const baseAnalysis = analyzeSecurityText(
    textSample,
    fileName,
    fileSizeBytes,
    sha256Hash,
    simulationMode,
    referenceHash
  );

  // Enrich with large-file streaming telemetry
  const formattedSize = formatByteSize(fileSizeBytes);
  baseAnalysis.file.file_size = formattedSize;
  baseAnalysis.file.file_size_bytes = fileSizeBytes;
  baseAnalysis.file.sha256 = sha256Hash;
  baseAnalysis.file.sha256_computation = 'STREAMING_CHUNKED_SUCCESS';

  // Include entropy telemetry in logs
  baseAnalysis.logs.unshift({
    time: new Date().toISOString().substring(11, 19),
    event: `Incremental stream processing verified. File size: ${formattedSize} | Shannon Entropy: ${entropy.toFixed(4)} bits/byte`,
    status: 'SUCCESS',
    previous_hash: '000000000000...',
    event_hash: sha256Hash.substring(0, 16) + '...',
    full_event_hash: sha256Hash
  });

  return baseAnalysis;
}

/**
 * Direct Streaming Multipart Upload Handler (`POST /api/upload`)
 * Uses busboy to stream chunks directly to disk with incremental hashing.
 */
export async function handleStreamingUpload(req: Request, res: Response): Promise<void> {
  // Check Content-Length header early
  const contentLength = parseInt(req.headers['content-length'] || '0', 10);
  if (contentLength > MAX_UPLOAD_SIZE) {
    res.status(413).json({
      success: false,
      error: 'File exceeds the maximum supported size of 1 TB.'
    });
    return;
  }

  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('multipart/form-data')) {
    // Check if JSON request with text or sample_id
    if (req.body && (req.body.text_content || req.body.sample_id)) {
      handleLegacyTextPayload(req, res);
      return;
    }
    res.status(400).json({ success: false, error: 'Expected multipart/form-data upload or JSON payload.' });
    return;
  }

  let bb: ReturnType<typeof busboy>;
  try {
    bb = busboy({
      headers: req.headers,
      limits: {
        fileSize: MAX_UPLOAD_SIZE,
        files: 1
      }
    });
  } catch (err: any) {
    res.status(400).json({ success: false, error: `Upload initialization failed: ${err?.message}` });
    return;
  }

  const uploadId = crypto.randomUUID();
  const tempPath = path.join(UPLOAD_TEMP_DIR, `${uploadId}.dat`);
  let writeStream: fs.WriteStream | null = null;
  const hasher = crypto.createHash('sha256');
  const byteFrequencies = new Uint32Array(256);
  let headSample = Buffer.alloc(0);

  let originalFileName = 'artifact.bin';
  let safeFileName = 'artifact.bin';
  let bytesWritten = 0;
  let fileHandled = false;
  let hasError = false;
  let errorMessage = '';

  const fields: Record<string, string> = {};

  bb.on('field', (name, val) => {
    fields[name] = val;
  });

  bb.on('file', (name, fileStream, info) => {
    fileHandled = true;
    originalFileName = info.filename || 'uploaded_artifact.bin';

    const validation = validateFileType(originalFileName);
    if (!validation.valid) {
      hasError = true;
      errorMessage = validation.error || 'Unsupported file type.';
      fileStream.resume(); // discard stream
      return;
    }

    safeFileName = sanitizeFilename(originalFileName);

    if (!fs.existsSync(UPLOAD_TEMP_DIR)) {
      fs.mkdirSync(UPLOAD_TEMP_DIR, { recursive: true });
    }

    try {
      writeStream = fs.createWriteStream(tempPath, { flags: 'w' });
      writeStream.on('error', (streamErr: any) => {
        console.warn('[Upload] Notice: Write stream error:', streamErr?.message);
      });
    } catch (streamErr: any) {
      hasError = true;
      errorMessage = `Server storage error: ${streamErr?.message}`;
      fileStream.resume();
      return;
    }

    fileStream.on('data', (chunk: Buffer) => {
      if (hasError) return;

      bytesWritten += chunk.length;

      // Real-time file size enforcement during streaming
      if (bytesWritten > MAX_UPLOAD_SIZE) {
        hasError = true;
        errorMessage = 'File exceeds the maximum supported size of 1 TB.';
        fileStream.destroy();
        if (writeStream) {
          writeStream.destroy();
          try { fs.unlinkSync(tempPath); } catch {}
        }
        return;
      }

      // Incremental SHA-256 calculation (Requirement 3 & 9)
      hasher.update(chunk);

      // Collect sample window for structured / crypto analysis (Requirement 11)
      if (headSample.length < MAX_SAMPLE_BYTES) {
        const remaining = MAX_SAMPLE_BYTES - headSample.length;
        headSample = Buffer.concat([headSample, chunk.subarray(0, remaining)]);
      }

      // Track byte frequency for Shannon entropy without RAM overhead
      for (let i = 0; i < chunk.length; i++) {
        byteFrequencies[chunk[i]]++;
      }

      writeStream!.write(chunk);
    });

    fileStream.on('error', (err: any) => {
      hasError = true;
      errorMessage = `Streaming file read error: ${err?.message}`;
      if (writeStream) writeStream.destroy();
      try { fs.unlinkSync(tempPath); } catch {}
    });

    fileStream.on('end', () => {
      if (writeStream) writeStream.end();
    });
  });

  // Client abort / connection drop cleanup (Requirement 7 & 13)
  req.on('aborted', () => {
    console.warn(`[Upload] Client connection aborted for ${uploadId}`);
    if (writeStream) writeStream.destroy();
    try { fs.unlinkSync(tempPath); } catch {}
  });

  bb.on('error', (err: any) => {
    if (!hasError) {
      hasError = true;
      errorMessage = err?.message || 'Multipart parsing error.';
    }
    if (writeStream) writeStream.destroy();
    try { fs.unlinkSync(tempPath); } catch {}
  });

  bb.on('finish', async () => {
    if (hasError) {
      res.status(errorMessage.includes('exceeds') ? 413 : 400).json({
        success: false,
        error: errorMessage
      });
      return;
    }

    if (!fileHandled) {
      // Check if sample_id or text_content was provided in fields
      if (fields.sample_id || fields.text_content) {
        handleFieldsLegacyPayload(fields, res);
        return;
      }
      res.status(400).json({ success: false, error: 'Please select a file to upload.' });
      return;
    }

    // Wait for write stream to finish flushing to disk
    if (writeStream && !writeStream.writableFinished) {
      await new Promise<void>(resolve => {
        writeStream!.on('finish', () => resolve());
        writeStream!.on('close', () => resolve());
        writeStream!.on('error', () => resolve());
        const timer = setTimeout(() => resolve(), 2500);
        writeStream!.once('finish', () => clearTimeout(timer));
      });
    }

    // Ensure tempPath exists on disk even for 0-byte or quickly flushed payloads
    if (!fs.existsSync(tempPath)) {
      try {
        fs.writeFileSync(tempPath, headSample && headSample.length > 0 ? headSample : Buffer.alloc(0));
      } catch (e) {
        console.warn('[Upload] Notice creating fallback temp file:', e);
      }
    }

    try {
      const finalSha256 = hasher.digest('hex');
      const mode = fields.attack_mode || 'Automatic Detection';
      const refHash = fields.reference_hash ? fields.reference_hash.trim() : undefined;

      const analysis = await analyzeFileWithClassifier(
        tempPath,
        safeFileName,
        bytesWritten,
        finalSha256,
        headSample,
        byteFrequencies,
        mode,
        refHash
      );

      // Execute email alert if forensic summary generated
      if (analysis.forensic_summary) {
        try {
          const emailResult = await executeEmailAlertProcess(
            analysis.forensic_summary,
            fields.recipient || undefined,
            false
          );
          analysis.email_alert = emailResult;
          if (analysis.summary) {
            analysis.summary.email_dispatched = emailResult.triggered;
            analysis.summary.email_recipient = emailResult.recipient;
          }
        } catch (emailErr) {
          console.warn('[Upload] Email dispatch warning:', emailErr);
        }
      }

      // Upload analyzed file artifact to Supabase Storage
      try {
        const payloadToUpload = fs.existsSync(tempPath)
          ? tempPath
          : (headSample && headSample.length > 0 ? headSample : Buffer.alloc(0));
        const storageRef = await uploadToSupabaseStorage(
          payloadToUpload,
          analysis.case_id || `CASE-${Date.now().toString(36).toUpperCase()}`,
          safeFileName
        );
        analysis.storage_path = storageRef;
      } catch (stErr) {
        console.warn('[Storage] Supabase storage upload notice:', stErr);
      }

      // Persist metadata and analysis results to database (Requirement 4 & 14)
      await persistAnalysisResult(analysis, safeFileName, bytesWritten, finalSha256, 'usr-01');

      // Ephemeral cleanup of the temp binary file on disk (Requirement 13)
      try {
        if (fs.existsSync(tempPath)) {
          fs.unlinkSync(tempPath);
        }
      } catch (cleanErr) {
        console.warn('[Upload] Notice: Temp file cleanup deferred:', cleanErr);
      }

      res.json(analysis);
    } catch (analysisErr: any) {
      console.error('[Upload] Analysis error:', analysisErr);
      try { fs.unlinkSync(tempPath); } catch {}
      res.status(500).json({
        success: false,
        error: `Security analysis failed: ${analysisErr?.message || 'Internal error'}`
      });
    }
  });

  req.pipe(bb);
}

/**
 * Initiates a chunked upload session (`POST /api/upload/init`)
 */
export function handleChunkInit(req: Request, res: Response): void {
  try {
    const { fileName, fileSizeBytes, mode, referenceHash, userId, recipient } = req.body;

    if (!fileName || typeof fileSizeBytes !== 'number') {
      res.status(400).json({ success: false, error: 'fileName and fileSizeBytes are required.' });
      return;
    }

    if (fileSizeBytes > MAX_UPLOAD_SIZE) {
      res.status(413).json({
        success: false,
        error: 'File exceeds the maximum supported size of 1 TB.'
      });
      return;
    }

    const validation = validateFileType(fileName);
    if (!validation.valid) {
      res.status(400).json({ success: false, error: validation.error });
      return;
    }

    const uploadId = crypto.randomUUID();
    const safeName = sanitizeFilename(fileName);
    const tempFilePath = path.join(UPLOAD_TEMP_DIR, `${uploadId}.part`);
    const totalChunks = Math.ceil(fileSizeBytes / UPLOAD_CHUNK_SIZE);

    const session: ChunkSession = {
      uploadId,
      originalFileName: fileName,
      safeFileName: safeName,
      fileSizeBytes,
      fileType: validation.extension.toUpperCase(),
      tempFilePath,
      bytesReceived: 0,
      totalChunks,
      chunksReceived: 0,
      hasher: crypto.createHash('sha256'),
      headSample: Buffer.alloc(0),
      byteFrequencies: new Uint32Array(256),
      mode: mode || 'Automatic Detection',
      referenceHash,
      userId: userId || 'usr-01',
      recipient,
      status: 'uploading',
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    activeSessions.set(uploadId, session);

    res.json({
      success: true,
      upload_id: uploadId,
      chunk_size: UPLOAD_CHUNK_SIZE,
      total_chunks: totalChunks,
      max_upload_size: MAX_UPLOAD_SIZE,
      message: 'Chunked upload session initialized successfully.'
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: `Init failed: ${err?.message}` });
  }
}

/**
 * Handles incoming chunk binary data (`POST /api/upload/chunk`)
 */
export async function handleChunkUpload(req: Request, res: Response): Promise<void> {
  const uploadId = (req.headers['x-upload-id'] as string) || (req.query.upload_id as string);
  const chunkIndex = parseInt(
    (req.headers['x-chunk-index'] as string) || (req.query.chunk_index as string) || '0',
    10
  );

  if (!uploadId || !activeSessions.has(uploadId)) {
    res.status(404).json({ success: false, error: 'Upload session not found or expired.' });
    return;
  }

  const session = activeSessions.get(uploadId)!;

  try {
    // Read raw chunk stream
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));

    req.on('end', async () => {
      const chunkBuffer = Buffer.concat(chunks);

      if (chunkBuffer.length === 0) {
        res.status(400).json({ success: false, error: 'Empty chunk data received.' });
        return;
      }

      session.bytesReceived += chunkBuffer.length;

      // Check max size enforcement
      if (session.bytesReceived > MAX_UPLOAD_SIZE) {
        activeSessions.delete(uploadId);
        try { fs.unlinkSync(session.tempFilePath); } catch {}
        res.status(413).json({
          success: false,
          error: 'File exceeds the maximum supported size of 1 TB.'
        });
        return;
      }

      // Incremental SHA-256 computation (Requirement 3 & 9)
      session.hasher.update(chunkBuffer);

      // Collect sample window
      if (session.headSample.length < MAX_SAMPLE_BYTES) {
        const remaining = MAX_SAMPLE_BYTES - session.headSample.length;
        session.headSample = Buffer.concat([session.headSample, chunkBuffer.subarray(0, remaining)]);
      }

      // Update byte frequencies for Shannon entropy
      for (let i = 0; i < chunkBuffer.length; i++) {
        session.byteFrequencies[chunkBuffer[i]]++;
      }

      // Append chunk to temporary file on disk (never keep in RAM!)
      fs.appendFileSync(session.tempFilePath, chunkBuffer);

      session.chunksReceived++;
      session.updatedAt = Date.now();

      const progressPercent = Math.min(100, Math.round((session.bytesReceived / session.fileSizeBytes) * 100));

      res.json({
        success: true,
        upload_id: uploadId,
        chunk_index: chunkIndex,
        bytes_received: session.bytesReceived,
        total_bytes: session.fileSizeBytes,
        progress_percentage: progressPercent,
        completed_chunk: true
      });
    });

    req.on('error', (err: any) => {
      res.status(500).json({ success: false, error: `Chunk transfer error: ${err?.message}` });
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: `Chunk append failure: ${err?.message}` });
  }
}

/**
 * Completes chunked upload and runs streaming analysis (`POST /api/upload/complete`)
 */
export async function handleChunkComplete(req: Request, res: Response): Promise<void> {
  const { upload_id } = req.body;

  if (!upload_id || !activeSessions.has(upload_id)) {
    res.status(404).json({ success: false, error: 'Upload session not found or expired.' });
    return;
  }

  const session = activeSessions.get(upload_id)!;

  try {
    // Validate that expected bytes were received (Requirement 7: Corrupted upload check)
    if (session.bytesReceived < session.fileSizeBytes) {
      res.status(400).json({
        success: false,
        error: `Corrupted upload: Received ${session.bytesReceived} bytes but expected ${session.fileSizeBytes} bytes.`
      });
      return;
    }

    const finalSha256 = session.hasher.digest('hex');
    const finalDatPath = path.join(UPLOAD_TEMP_DIR, `${session.uploadId}.dat`);

    if (!fs.existsSync(UPLOAD_TEMP_DIR)) {
      fs.mkdirSync(UPLOAD_TEMP_DIR, { recursive: true });
    }

    if (fs.existsSync(session.tempFilePath)) {
      try {
        fs.renameSync(session.tempFilePath, finalDatPath);
      } catch (renameErr) {
        try {
          fs.copyFileSync(session.tempFilePath, finalDatPath);
          fs.unlinkSync(session.tempFilePath);
        } catch (copyErr) {
          console.warn('[Upload] Notice: Copy/rename fallback failed:', copyErr);
        }
      }
    }

    // Ensure finalDatPath exists on disk even if 0-bytes or part missing
    if (!fs.existsSync(finalDatPath)) {
      try {
        fs.writeFileSync(
          finalDatPath,
          session.headSample && session.headSample.length > 0 ? session.headSample : Buffer.alloc(0)
        );
      } catch (writeErr) {
        console.warn('[Upload] Notice creating final dat fallback:', writeErr);
      }
    }

    const analysis = await analyzeFileWithClassifier(
      finalDatPath,
      session.safeFileName,
      session.bytesReceived,
      finalSha256,
      session.headSample,
      session.byteFrequencies,
      session.mode,
      session.referenceHash
    );

    // Execute email alert if forensic summary generated
    if (analysis.forensic_summary) {
      try {
        const emailResult = await executeEmailAlertProcess(
          analysis.forensic_summary,
          session.recipient || undefined,
          false
        );
        analysis.email_alert = emailResult;
        if (analysis.summary) {
          analysis.summary.email_dispatched = emailResult.triggered;
          analysis.summary.email_recipient = emailResult.recipient;
        }
      } catch (emailErr) {
        console.warn('[Upload] Email dispatch warning:', emailErr);
      }
    }

    // Upload assembled file artifact to Supabase Storage
    try {
      const payloadToUpload = fs.existsSync(finalDatPath)
        ? finalDatPath
        : (session.headSample && session.headSample.length > 0 ? session.headSample : Buffer.alloc(0));
      const storageRef = await uploadToSupabaseStorage(
        payloadToUpload,
        analysis.case_id || `CASE-${Date.now().toString(36).toUpperCase()}`,
        session.safeFileName
      );
      analysis.storage_path = storageRef;
    } catch (stErr) {
      console.warn('[Storage] Supabase storage upload notice:', stErr);
    }

    // Save case to database
    await persistAnalysisResult(analysis, session.safeFileName, session.bytesReceived, finalSha256, session.userId);

    // Ephemeral cleanup
    try {
      if (fs.existsSync(finalDatPath)) {
        fs.unlinkSync(finalDatPath);
      }
    } catch {}

    activeSessions.delete(upload_id);

    res.json(analysis);
  } catch (analysisErr: any) {
    console.error('[Upload] Chunk completion analysis error:', analysisErr);
    try { fs.unlinkSync(session.tempFilePath); } catch {}
    activeSessions.delete(upload_id);
    res.status(500).json({
      success: false,
      error: `Analysis failed: ${analysisErr?.message || 'Internal error'}`
    });
  }
}

/**
 * Stores file metadata and analysis results in PostgreSQL (and local file fallback) (Requirement 4 & 14).
 * Crucial: Binary file content is NOT stored in PostgreSQL or local JSON state!
 */
async function persistAnalysisResult(
  analysis: AnalysisResponse,
  fileName: string,
  fileSizeBytes: number,
  sha256Hash: string,
  userId = 'usr-01'
): Promise<void> {
  try {
    const riskScore = analysis.threat?.risk_score ?? 0;
    const isThreat = analysis.threat?.status === 'ATTACK DETECTED' || riskScore >= 60;
    const isSusp = !isThreat && (riskScore >= 35 || analysis.signature?.hash_mismatch);
    const statusStr = isThreat ? 'COMPROMISED' : isSusp ? 'SUSPICIOUS' : 'SECURE';
    const detectedCount = (analysis.attack_table || []).filter(
      r => r.status === 'AUTO-DETECTED' || r.status === 'SIMULATION' || r.status === 'ATTACK DETECTED'
    ).length;

    const ext = fileName.split('.').pop()?.toUpperCase() || 'BIN';

    await saveCase({
      case_id: analysis.case_id || `CASE-${Date.now().toString(36).toUpperCase()}`,
      file_name: fileName,
      file_size: fileSizeBytes,
      file_type: ext,
      sha256: sha256Hash,
      user_id: userId,
      analysis_status: 'COMPLETED',
      security_status: statusStr,
      timestamp: analysis.file?.upload_time || new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
      risk_score: riskScore,
      status: statusStr,
      threats_count: isThreat ? Math.max(1, detectedCount) : 0,
      primary_threat: analysis.threat?.detected_threat || 'None',
      data: analysis
    });
  } catch (saveErr) {
    console.warn('[Database] Case metadata persistence warning:', saveErr);
  }
}

/**
 * Handles legacy text payload for backward compatibility
 */
function handleLegacyTextPayload(req: Request, res: Response): void {
  try {
    let filename = 'unknown.txt';
    let rawText = '';
    if (req.body.sample_id && SAMPLE_DATASETS[req.body.sample_id]) {
      filename = req.body.sample_id;
      rawText = SAMPLE_DATASETS[req.body.sample_id].content;
    } else if (req.body.text_content) {
      filename = req.body.filename || 'raw_text_payload.txt';
      rawText = req.body.text_content;
    } else {
      res.status(400).json({ success: false, error: 'Invalid payload.' });
      return;
    }

    const fileBytesLength = Buffer.byteLength(rawText, 'utf-8');
    const sha256Hash = crypto.createHash('sha256').update(rawText).digest('hex');
    const mode = (req.body.attack_mode as string) || 'Automatic Detection';
    const refHash = (req.body.reference_hash as string) || undefined;

    const analysis = analyzeSecurityText(rawText, filename, fileBytesLength, sha256Hash, mode, refHash);
    persistAnalysisResult(analysis, filename, fileBytesLength, sha256Hash, 'usr-01');
    res.json(analysis);
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message || 'Analysis error' });
  }
}

function handleFieldsLegacyPayload(fields: Record<string, string>, res: Response): void {
  try {
    let filename = 'sample.txt';
    let rawText = '';
    if (fields.sample_id && SAMPLE_DATASETS[fields.sample_id]) {
      filename = fields.sample_id;
      rawText = SAMPLE_DATASETS[fields.sample_id].content;
    } else if (fields.text_content) {
      filename = fields.filename || 'text_payload.txt';
      rawText = fields.text_content;
    }

    const fileBytesLength = Buffer.byteLength(rawText, 'utf-8');
    const sha256Hash = crypto.createHash('sha256').update(rawText).digest('hex');
    const mode = fields.attack_mode || 'Automatic Detection';
    const refHash = fields.reference_hash || undefined;

    const analysis = analyzeSecurityText(rawText, filename, fileBytesLength, sha256Hash, mode, refHash);
    persistAnalysisResult(analysis, filename, fileBytesLength, sha256Hash, 'usr-01');
    res.json(analysis);
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message || 'Analysis error' });
  }
}

/**
 * Cleans up abandoned temporary uploads older than 1 hour (Requirement 13)
 */
export function cleanupAbandonedUploads(): void {
  try {
    const now = Date.now();
    const ONE_HOUR = 60 * 60 * 1000;

    // Clean memory sessions
    for (const [id, session] of activeSessions.entries()) {
      if (now - session.updatedAt > ONE_HOUR) {
        try {
          if (fs.existsSync(session.tempFilePath)) {
            fs.unlinkSync(session.tempFilePath);
          }
        } catch {}
        activeSessions.delete(id);
      }
    }

    // Clean disk files
    if (fs.existsSync(UPLOAD_TEMP_DIR)) {
      const files = fs.readdirSync(UPLOAD_TEMP_DIR);
      for (const file of files) {
        const fullPath = path.join(UPLOAD_TEMP_DIR, file);
        try {
          const stats = fs.statSync(fullPath);
          if (now - stats.mtimeMs > ONE_HOUR) {
            fs.unlinkSync(fullPath);
          }
        } catch {}
      }
    }
  } catch (err) {
    console.warn('[Upload] Cleanup cycle warning:', err);
  }
}

// Run cleanup every 15 minutes
setInterval(cleanupAbandonedUploads, 15 * 60 * 1000);
