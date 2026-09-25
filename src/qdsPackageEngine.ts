import { QdsPackage, QdsSignatureAlgorithm, QdsQuantumProtocol } from './types';

// Helper to compute SHA-256 in browser or Node
export async function computeHashSha256(text: string): Promise<string> {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // Fallback simple deterministic hash if crypto not available
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0, ch; i < text.length; i++) {
    ch = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const p1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const p2 = (h2 >>> 0).toString(16).padStart(8, '0');
  return (p1 + p2 + p1 + p2 + p1 + p2 + p1 + p2).substring(0, 64);
}

export function generateRandomHex(byteLength: number): string {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < byteLength * 2; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

export interface QdsSignOptions {
  filename: string;
  content: string;
  fileType?: string;
  algorithm?: QdsSignatureAlgorithm;
  signerIdentity?: string;
  signerEmail?: string;
  signerRole?: string;
  signerOrg?: string;
  quantumProtocol?: QdsQuantumProtocol;
  qberBaseline?: number;
}

export async function createQdsPackage(opts: QdsSignOptions): Promise<QdsPackage> {
  const filename = opts.filename || 'document.txt';
  const content = opts.content || '';
  const now = new Date();
  const timestamp = now.toISOString();
  const epoch_ms = now.getTime();
  const fileBytes = new TextEncoder().encode(content).length;

  const sha256 = await computeHashSha256(content);
  const algorithm = opts.algorithm || 'ML-DSA-65 (Dilithium3)';
  const isPostQuantum = algorithm.startsWith('ML-DSA') || algorithm.startsWith('Falcon') || algorithm.startsWith('SPHINCS');

  const nonce = generateRandomHex(16); // 32 hex chars
  const sessionId = `SESS-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${generateRandomHex(3).toUpperCase()}`;

  // Generate realistic simulated digital signature based on algorithm
  const sigPrefix = isPostQuantum ? 'PQC-SIG' : 'CLASSICAL-SIG';
  const digitalSignature = `${sigPrefix}-${algorithm.replace(/[^A-Za-z0-9]/g, '')}-${generateRandomHex(32)}`;

  const signerIdentity = opts.signerIdentity || 'Dr. Alice Vance';
  const signerEmail = opts.signerEmail || 'alice@quantum-vault.internal';
  const signerRole = opts.signerRole || 'Chief Cryptographic Officer';
  const signerOrg = opts.signerOrg || 'National Quantum Security Laboratory';
  const keyFingerprint = `SHA256:${generateRandomHex(16).toUpperCase()}`;
  const certSerial = `SN-${generateRandomHex(8).toUpperCase()}`;

  const qberBaseline = opts.qberBaseline !== undefined ? opts.qberBaseline : 1.25;

  const pkgId = `QDS-PKG-${now.getFullYear()}-${generateRandomHex(4).toUpperCase()}`;

  const pkg: QdsPackage = {
    format: 'QDS-PACKAGE-v2.0',
    package_id: pkgId,
    created_at: timestamp,
    original_artifact: {
      filename,
      file_type: opts.fileType || filename.split('.').pop()?.toUpperCase() || 'TXT',
      mime_type: getMimeType(filename),
      file_size_bytes: fileBytes,
      file_size_formatted: formatBytes(fileBytes),
      raw_content: content,
      is_binary: false
    },
    cryptography: {
      sha256,
      signature_algorithm: algorithm,
      signature_type: isPostQuantum ? 'POST_QUANTUM' : 'CLASSICAL',
      digital_signature: digitalSignature,
      nonce,
      session_id: sessionId,
      timestamp,
      epoch_ms
    },
    signer: {
      identity: signerIdentity,
      email: signerEmail,
      role: signerRole,
      organization: signerOrg,
      public_key: `-----BEGIN PUBLIC KEY-----\n${generateRandomHex(48)}\n-----END PUBLIC KEY-----`,
      key_fingerprint: keyFingerprint,
      certificate_serial: certSerial,
      trust_status: 'AUTHORIZED'
    },
    quantum_evidence: {
      protocol: opts.quantumProtocol || 'BB84-Decoy-State',
      qber_baseline: qberBaseline,
      observed_qber: qberBaseline,
      raw_key_bits: 4096,
      sifted_key_bits: 2048,
      quantum_state_fidelity: 0.994,
      phase_error_rate: 1.10,
      decoy_state_yield: 0.985,
      channel_attenuation_db: 0.18,
      channel_status: 'SECURE',
      eve_detected: false,
      quantum_simulation_note: 'Quantum channel metrics simulated via physical statevector telemetry (distinguished from classical/PQC math).'
    },
    metadata: {
      version: '2.0',
      app: 'Q-SHIELD Security & Verification Platform',
      generator: 'QDS Signing Engine v2.0',
      immutable_hash: ''
    }
  };

  // Compute envelope immutable hash over canonical representation
  const canonicalString = JSON.stringify({
    pkgId: pkg.package_id,
    sha256: pkg.cryptography.sha256,
    sig: pkg.cryptography.digital_signature,
    nonce: pkg.cryptography.nonce,
    session: pkg.cryptography.session_id,
    signer: pkg.signer.identity,
    qber: pkg.quantum_evidence.qber_baseline
  });
  pkg.metadata.immutable_hash = await computeHashSha256(canonicalString);

  return pkg;
}

export type QdsAttackVectorId =
  | 'REPLAY_ATTACK'
  | 'SIGNATURE_FORGERY'
  | 'PAYLOAD_TAMPERING'
  | 'QUANTUM_CHANNEL_EAVESDROPPING'
  | 'SIGNER_IMPERSONATION'
  | 'ALGORITHM_DOWNGRADE';

export interface AttackVectorDefinition {
  id: QdsAttackVectorId;
  title: string;
  category: 'Protocol & State' | 'Classical Cryptography' | 'Quantum Channel' | 'Identity & PKI';
  severity: 'Critical' | 'High' | 'Medium';
  standardsReference: string;
  mechanism: string;
  tamperedFields: string[];
}

export const QDS_ATTACK_VECTORS: AttackVectorDefinition[] = [
  {
    id: 'REPLAY_ATTACK',
    title: 'Stateful Replay Attack (Nonce Reuse & Stale Timestamp)',
    category: 'Protocol & State',
    severity: 'High',
    standardsReference: 'NIST SP 800-63B § 5.2.8 / RFC 5280',
    mechanism: 'Adversary re-transmits a previously captured valid signed package. Nonce is already recorded in the active ledger, and the timestamp freshness delta has expired (> 300s).',
    tamperedFields: ['cryptography.nonce', 'cryptography.session_id', 'cryptography.timestamp', 'cryptography.epoch_ms']
  },
  {
    id: 'SIGNATURE_FORGERY',
    title: 'Digital Signature Forgery / Bit Alteration',
    category: 'Classical Cryptography',
    severity: 'Critical',
    standardsReference: 'NIST FIPS 186-5 / FIPS 204 (ML-DSA)',
    mechanism: 'Adversary tampers with the digital signature bytes or crafts an illegitimate mathematical proof without knowledge of the private signing key.',
    tamperedFields: ['cryptography.digital_signature']
  },
  {
    id: 'PAYLOAD_TAMPERING',
    title: 'Payload Tampering (In-Transit Data Alteration)',
    category: 'Classical Cryptography',
    severity: 'Critical',
    standardsReference: 'NIST FIPS 180-4 (Secure Hash Standard)',
    mechanism: 'The underlying file content or transaction values are modified in transit without updating the SHA-256 digest or signature, inducing a cryptographic mismatch.',
    tamperedFields: ['original_artifact.raw_content', 'original_artifact.file_size_bytes']
  },
  {
    id: 'QUANTUM_CHANNEL_EAVESDROPPING',
    title: 'Quantum Channel Manipulation (Eve Intercept & Disturbance)',
    category: 'Quantum Channel',
    severity: 'Critical',
    standardsReference: 'Bennett-Brassard (BB84) & QDS Telemetry Bounds',
    mechanism: 'Simulated eavesdropper Eve performs projective measurement on entangled key pairs in transit, driving QBER well above the 11.0% abort threshold and collapsing state fidelity.',
    tamperedFields: ['quantum_evidence.observed_qber', 'quantum_evidence.quantum_state_fidelity', 'quantum_evidence.channel_status', 'quantum_evidence.eve_detected']
  },
  {
    id: 'SIGNER_IMPERSONATION',
    title: 'Signer Impersonation & Rogue Certificate Authority',
    category: 'Identity & PKI',
    severity: 'High',
    standardsReference: 'ITU-T X.509 / RFC 5280',
    mechanism: 'The package signer identity and public key are substituted with an unauthorized credential not anchored to a trusted Root CA.',
    tamperedFields: ['signer.identity', 'signer.email', 'signer.public_key', 'signer.key_fingerprint', 'signer.trust_status']
  },
  {
    id: 'ALGORITHM_DOWNGRADE',
    title: 'Post-Quantum Algorithm Downgrade Attack',
    category: 'Classical Cryptography',
    severity: 'High',
    standardsReference: 'NIST SP 800-131A / PQC Migration Guidelines',
    mechanism: 'Attacker forces signature algorithm downgrade from post-quantum (ML-DSA-65) to vulnerable legacy classical algorithm (RSA-1024) susceptible to Shor factoring.',
    tamperedFields: ['cryptography.signature_algorithm', 'cryptography.signature_type', 'cryptography.digital_signature']
  }
];

/**
 * Creates an isolated copy of the QdsPackage and mutates only the copy.
 * The original package is completely preserved.
 */
export function cloneAndAttackPackage(
  original: QdsPackage,
  vectorId: QdsAttackVectorId
): QdsPackage {
  // Deep clone to guarantee original remains completely untouched
  const attacked: QdsPackage = JSON.parse(JSON.stringify(original));
  const vector = QDS_ATTACK_VECTORS.find(v => v.id === vectorId);
  const now = new Date();

  attacked.package_id = `${original.package_id}_ATTACKED_${vectorId}`;
  attacked.metadata.is_attack_copy = true;
  attacked.metadata.attack_parent_id = original.package_id;
  attacked.metadata.attack_applied = {
    vector_id: vectorId,
    title: vector ? vector.title : vectorId,
    category: vector ? vector.category : 'Adversarial Mutation',
    timestamp: now.toISOString(),
    description: vector ? vector.mechanism : 'Adversarial tampering applied',
    tampered_fields: vector ? vector.tamperedFields : []
  };

  switch (vectorId) {
    case 'REPLAY_ATTACK': {
      // Replay attack: stale nonce, expired timestamp (> 30 days ago), expired session
      const past = new Date(Date.now() - 30 * 24 * 3600 * 1000);
      attacked.cryptography.nonce = 'REUSED-NONCE-8f9b2c3d4e5f6a1b';
      attacked.cryptography.session_id = 'SESS-20251104-EXPIRED-9921';
      attacked.cryptography.timestamp = past.toISOString();
      attacked.cryptography.epoch_ms = past.getTime();
      break;
    }

    case 'SIGNATURE_FORGERY': {
      // Corrupt the signature bytes
      const origSig = attacked.cryptography.digital_signature;
      attacked.cryptography.digital_signature = `FORGED-${origSig.slice(0, 16)}CORRUPT_BYTES_${generateRandomHex(12)}_MATH_FAIL`;
      break;
    }

    case 'PAYLOAD_TAMPERING': {
      // Tamper with the raw content (e.g., inject malicious command or alter transaction)
      const origText = attacked.original_artifact.raw_content;
      let tamperedText = origText;
      if (origText.includes('Amount:') || origText.includes('100') || origText.includes('$')) {
        tamperedText = origText.replace(/\$?[0-9,.]+/g, '$9,850,000.00 [TAMPERED_TRANSFER]');
      } else {
        tamperedText = `${origText}\n\n[ADVERSARY_INJECTION: Unauthorized administrative override command appended without re-signing payload]`;
      }
      attacked.original_artifact.raw_content = tamperedText;
      attacked.original_artifact.file_size_bytes = new TextEncoder().encode(tamperedText).length;
      attacked.original_artifact.file_size_formatted = formatBytes(attacked.original_artifact.file_size_bytes);
      // Notice: sha256 is intentionally left as the OLD hash to simulate in-transit tampering!
      break;
    }

    case 'QUANTUM_CHANNEL_EAVESDROPPING': {
      // Eve intervenes: QBER spikes to 14.85%, fidelity collapses, Eve flagged
      attacked.quantum_evidence.observed_qber = 14.85;
      attacked.quantum_evidence.quantum_state_fidelity = 0.712;
      attacked.quantum_evidence.channel_status = 'COMPROMISED';
      attacked.quantum_evidence.eve_detected = true;
      attacked.quantum_evidence.phase_error_rate = 13.90;
      break;
    }

    case 'SIGNER_IMPERSONATION': {
      attacked.signer.identity = 'Adversary Eve (Unauthorized Actor)';
      attacked.signer.email = 'eve.adversary@rogue-proxy.net';
      attacked.signer.role = 'Unverified External Entity';
      attacked.signer.organization = 'Rogue Shadow Autonomous System';
      attacked.signer.public_key = `-----BEGIN PUBLIC KEY-----\n${generateRandomHex(48)}ROGUE\n-----END PUBLIC KEY-----`;
      attacked.signer.key_fingerprint = `SHA256:0000000000000000ROGUE${generateRandomHex(8).toUpperCase()}`;
      attacked.signer.trust_status = 'UNTRUSTED';
      break;
    }

    case 'ALGORITHM_DOWNGRADE': {
      attacked.cryptography.signature_algorithm = 'RSA-PSS-2048'; // Downgraded
      attacked.cryptography.signature_type = 'CLASSICAL';
      attacked.cryptography.digital_signature = `DOWNGRADED-RSA1024-SIG-${generateRandomHex(24)}`;
      break;
    }
  }

  return attacked;
}

export interface PackageDiffItem {
  field: string;
  label: string;
  originalValue: string;
  attackedValue: string;
  severity: 'high' | 'critical' | 'medium';
}

export function computePackageDiff(original: QdsPackage, attacked: QdsPackage): PackageDiffItem[] {
  const diffs: PackageDiffItem[] = [];

  if (original.original_artifact.raw_content !== attacked.original_artifact.raw_content) {
    diffs.push({
      field: 'original_artifact.raw_content',
      label: 'File Payload / Content',
      originalValue: original.original_artifact.raw_content.slice(0, 80) + '...',
      attackedValue: attacked.original_artifact.raw_content.slice(0, 80) + '...',
      severity: 'critical'
    });
  }

  if (original.cryptography.digital_signature !== attacked.cryptography.digital_signature) {
    diffs.push({
      field: 'cryptography.digital_signature',
      label: 'Digital Signature',
      originalValue: original.cryptography.digital_signature.slice(0, 32) + '...',
      attackedValue: attacked.cryptography.digital_signature.slice(0, 32) + '...',
      severity: 'critical'
    });
  }

  if (original.cryptography.nonce !== attacked.cryptography.nonce) {
    diffs.push({
      field: 'cryptography.nonce',
      label: 'Cryptographic Nonce',
      originalValue: original.cryptography.nonce,
      attackedValue: attacked.cryptography.nonce,
      severity: 'high'
    });
  }

  if (original.cryptography.session_id !== attacked.cryptography.session_id) {
    diffs.push({
      field: 'cryptography.session_id',
      label: 'Session Identifier',
      originalValue: original.cryptography.session_id,
      attackedValue: attacked.cryptography.session_id,
      severity: 'high'
    });
  }

  if (original.cryptography.timestamp !== attacked.cryptography.timestamp) {
    diffs.push({
      field: 'cryptography.timestamp',
      label: 'Signature Timestamp',
      originalValue: original.cryptography.timestamp,
      attackedValue: attacked.cryptography.timestamp,
      severity: 'high'
    });
  }

  if (original.cryptography.signature_algorithm !== attacked.cryptography.signature_algorithm) {
    diffs.push({
      field: 'cryptography.signature_algorithm',
      label: 'Cryptographic Algorithm',
      originalValue: original.cryptography.signature_algorithm,
      attackedValue: attacked.cryptography.signature_algorithm,
      severity: 'high'
    });
  }

  if (original.quantum_evidence.observed_qber !== attacked.quantum_evidence.observed_qber) {
    diffs.push({
      field: 'quantum_evidence.observed_qber',
      label: 'Quantum Bit Error Rate (QBER)',
      originalValue: `${original.quantum_evidence.observed_qber}%`,
      attackedValue: `${attacked.quantum_evidence.observed_qber}%`,
      severity: 'critical'
    });
  }

  if (original.signer.identity !== attacked.signer.identity) {
    diffs.push({
      field: 'signer.identity',
      label: 'Signer Identity',
      originalValue: original.signer.identity,
      attackedValue: attacked.signer.identity,
      severity: 'critical'
    });
  }

  return diffs;
}

// Built-in Realistic Presets for Instant User Experience
export const QDS_PRESET_TEMPLATES: {
  id: string;
  name: string;
  filename: string;
  description: string;
  algorithm: QdsSignatureAlgorithm;
  content: string;
}[] = [
  {
    id: 'defense-auth',
    name: 'Defense Authorization Directive (PDF/TXT)',
    filename: 'DoD_Directive_QuantumAuth_2026.pdf',
    description: 'NIST FIPS 204 Dilithium3 signed defense operational order.',
    algorithm: 'ML-DSA-65 (Dilithium3)',
    content: `DEFENSE COMMUNICATIONS & CIPHER COMMAND
DIRECTIVE: AUTH-2026-ALPHA-09
CLASSIFICATION: TOP SECRET // QDS ENCRYPTED
ORIGINATOR: Dr. Alice Vance (Chief Cryptographic Officer)
DESTINATION: Western Node Quantum Terminal 04

OPERATIONAL DIRECTIVE:
1. Initialize Quantum Key Distribution protocol over 42km fiber ring.
2. Sift key pairs with baseline QBER bound < 2.0%.
3. Re-anchor all satellite telemetry via post-quantum digital signature standard FIPS 204 (ML-DSA-65).
4. All automated decryption keys must verify statevector entanglement fidelity >= 0.990.

AUTHENTICATION VERIFICATION:
Hash Integrity: SHA-256 Validated
Signer Certificate: Root DoD-PQC-CA v3 Valid
Status: AUTHORIZED`
  },
  {
    id: 'wire-transfer',
    name: 'FedWire Interbank Settlement $1,450,000 (JSON)',
    filename: 'fedwire_settlement_txn_8841.json',
    description: 'High-value banking transaction with stateful nonce and session ID.',
    algorithm: 'Falcon-512',
    content: `{
  "transaction_id": "FEDWIRE-TXN-2026-981249",
  "settlement_type": "RTGS_INTERBANK_CREDIT",
  "originating_bank": "FEDERAL_RESERVE_DISTRICT_12",
  "originating_bic": "FRNYUS33XXX",
  "beneficiary_bank": "QUANTUM_GLOBAL_VAULT",
  "beneficiary_bic": "QGVLUS44XXX",
  "currency": "USD",
  "amount": "1450000.00",
  "value_date": "2026-09-24",
  "audit_trail": {
    "initiator": "alice@quantum-vault.internal",
    "dual_custody_verified": true,
    "pqc_signature_required": true
  }
}`
  },
  {
    id: 'firmware-manifest',
    name: 'Satellite Avionics Firmware Manifest (TXT)',
    filename: 'firmware_manifest_leo_sat09.txt',
    description: 'Embedded flight computer firmware release signed with SPHINCS+ hash-based signatures.',
    algorithm: 'SPHINCS+-SHA2-128s',
    content: `AVIONICS FIRMWARE INTEGRITY SPECIFICATION
Platform: LEO Satellite Array Node-09
Firmware Build: v4.8.2-PQC-SECURE
Build Timestamp: 2026-09-20T14:30:00Z
Compiler: LLVM Embedded Toolchain 19.1
Target Architecture: RISC-V 64-bit Rad-Hard
Image Digest SHA-256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
Code Signing Authority: Space Cryptography Operations Unit
Integrity Validation: Hash & SPHINCS+ Signature Required Before Flash Write`
  },
  {
    id: 'health-record',
    name: 'Clinical Genomic Sequencing Consent (CSV)',
    filename: 'genomic_clinical_trial_record.csv',
    description: 'HIPAA-compliant medical genome trial record protected by quantum digital signature.',
    algorithm: 'ML-DSA-65 (Dilithium3)',
    content: `patient_pseudonym,trial_cohort,sequencing_panel,consent_verified,pqc_signed_by,timestamp
PT-9812-GEN,ONCOLOGY-PHASE3,WHOLE_GENOME_30X,TRUE,alice@quantum-vault.internal,2026-09-24T18:00:00Z
PT-9813-GEN,ONCOLOGY-PHASE3,WHOLE_GENOME_30X,TRUE,alice@quantum-vault.internal,2026-09-24T18:05:00Z
PT-9814-GEN,ONCOLOGY-PHASE3,TARGETED_EXOME_50X,TRUE,alice@quantum-vault.internal,2026-09-24T18:10:00Z`
  }
];

function getMimeType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'pdf': return 'application/pdf';
    case 'json': return 'application/json';
    case 'csv': return 'text/csv';
    case 'xml': return 'application/xml';
    default: return 'text/plain';
  }
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 bytes';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function exportPackageToJson(pkg: QdsPackage): string {
  return JSON.stringify(pkg, null, 2);
}

export function downloadPackageFile(pkg: QdsPackage) {
  const jsonStr = exportPackageToJson(pkg);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const safeName = pkg.original_artifact.filename.replace(/\.[^/.]+$/, '');
  link.href = url;
  link.download = `${safeName}.qds`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
