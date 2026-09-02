export interface FileMetadata {
  filename: string;
  file_type: string;
  mime_type?: string;
  magic_header?: string;
  file_size: string;
  file_size_bytes?: number;
  upload_time: string;
  sha256: string;
  sha256_computation?: string;
  reference_hash?: string;
  hash_match?: string;
  integrity_comparison?: string;
  integrity_status?: string;
}

export interface CryptographicVerificationInfo {
  verification_layer: string;
  cryptographic_status: string;
  mathematical_verification: 'VALID' | 'FAILED' | 'STRUCTURE_VALID' | 'PARTIALLY_VERIFIED' | 'UNAVAILABLE' | string;
  algorithm_detected: string;
  public_key_present: boolean;
  digest_verified: boolean;
  details: string;
  verification_badge: string;
  is_verified: boolean;
}

export interface CertificateAnalysisInfo {
  certificate_present: boolean;
  status: 'VALID' | 'INVALID' | 'UNTRUSTED' | 'NOT_FOUND' | string;
  subject: string;
  issuer: string;
  serial_number: string;
  version: string;
  valid_from: string;
  valid_until: string;
  validity_status: string;
  public_key_algorithm: string;
  public_key_size: string;
  signature_algorithm: string;
  key_usage: string[];
  extended_key_usage: string[];
  subject_alternative_name: string[];
  basic_constraints: string;
  fingerprint_sha256: string;
  fingerprint_sha1: string;
  is_self_signed: boolean;
  is_weak_key: boolean;
  trust_chain: 'VALID' | 'PARTIALLY_VERIFIED' | 'FAILED' | 'UNAVAILABLE' | string;
  trust_chain_details: string;
  revocation: {
    status: string;
    method: string;
    details: string;
  };
  security_warnings: string[];
}

export interface StatefulReplayInfo {
  is_stateful_replay: boolean;
  stateful_replay_type: 'STATEFUL_REPLAY_DETECTED' | 'FRESH_TRANSACTION' | 'STALE_TIMESTAMP' | string;
  matched_identifiers: Array<{
    type: string;
    value: string;
    first_seen: string;
    hit_count: number;
  }>;
  hit_count: number;
  first_seen: string;
  freshness_window_seconds: number;
  timestamp_freshness: 'FRESH' | 'STALE' | 'UNKNOWN' | 'PARSE_ERROR' | string;
  freshness_delta_seconds: number;
  store_type: string;
}

export interface DigitalSignatureInfo {
  signature_present: boolean;
  signature_status: string;
  signature_algorithm: string;
  signer_information: string;
  verification_result: string;
  hash_mismatch: boolean;
  indicators: string[];
  note: string;
}

export interface ThreatResult {
  status: string;
  detected_threat: string;
  threat_category: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  risk_score: number;
  confidence: number;
  reason: string;
  evidence: string[];
  first_action: string;
  recommendation: string;
  intensity: number;
  additional_threats?: string[];
  all_detected_threats?: ThreatResult[];
  scoring_model?: string;
}

export interface QuantumMetrics {
  qber: number;
  qber_percentage: string;
  mismatch_rate: number;
  mismatch_rate_percentage: string;
  matching_rate: number;
  matching_rate_percentage: string;
  quantum_risk: string;
  estimated_eavesdropping_probability: string;
  estimated_eavesdropping_probability_value?: number;
  security_level: string;
  assessment_note?: string;
  number_of_rounds: number;
  matches: number;
  mismatches: number;
  qber_threshold: string;
  state_preservation_fidelity: string;
  detection_mode?: string;
  disclaimer: string;
}

export interface PostQuantumAssessment {
  detected_algorithm: string;
  classical_security: string;
  quantum_security: string;
  pqc_status: string;
  nist_standard: string;
  migration_priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'COMPLETED / ADOPTED' | string;
  recommended_pqc: string;
  recommended_pqc_secondary: string;
  pqc_readiness_score: number;
  crypto_agility_score: number;
  technical_assessment: string;
  crypto_agility_rationale: string;
  is_quantum_safe: boolean;
  assessment_label: string;
}

export interface CBOMData {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: any;
  cryptoProperties: any;
}

export interface AttackTableRow {
  attack: string;
  status: 'AUTO-DETECTED' | 'NOT DETECTED' | 'SIMULATION' | string;
  risk: string;
  risk_score: number;
  reason: string;
}

export interface SecurityLog {
  time: string;
  event: string;
  status: 'SUCCESS' | 'WARNING' | 'ALERT' | 'ACTION_REQUIRED' | 'INFO' | string;
  previous_hash?: string;
  event_hash?: string;
  full_event_hash?: string;
}

export interface ForensicSummary {
  case_id: string;
  date_time: string;
  target_file: string;
  sha256: string;
  overall_status: 'THREAT DETECTED' | 'NORMAL / SYSTEM SECURE' | string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  threat_score: number;
  threat_indicators: string[];
  digital_signature_status: 'VALID' | 'INVALID' | 'MISMATCH' | 'PRESENT (UNVERIFIED)' | 'NOT AVAILABLE' | string;
  file_integrity: 'INTACT' | 'MODIFIED' | 'SUSPICIOUS' | string;
  quantum_metrics: {
    qber: string;
    mismatch_rate: string;
    matching_rate: string;
    eavesdrop_probability: string;
    quantum_risk: string;
    security_level: string;
  };
  timestamp_freshness: 'FRESH' | 'STALE' | string;
  forensic_findings: string;
  recommended_action: string;
  evidence: string[];
}

export interface EmailProcessStep {
  id: string;
  name: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped';
  duration_ms: number;
  details: string;
  timestamp: string;
}

export interface EmailTransmissionReceipt {
  message_id: string;
  dispatched_at: string;
  recipient: string;
  smtp_host: string;
  smtp_port: number;
  tls_cipher: string;
  payload_hash: string;
  total_duration_ms: number;
}

export interface EmailAlertStatus {
  success: boolean;
  triggered: boolean;
  status: 'SENT' | 'TEST_MODE_SIMULATED' | 'FAILED' | 'SKIPPED_LOW_RISK' | 'NOT_CONFIGURED' | string;
  message: string;
  recipient: string;
  subject?: string;
  body_preview?: string;
  full_body?: string;
  attachment_name?: string;
  is_test_mode: boolean;
  smtp_server?: string;
  smtp_port?: number;
  timestamp?: string;
  error?: string;
  gmail_compose_url?: string;
  mailto_url?: string;
  pipeline_steps?: EmailProcessStep[];
  transmission_receipt?: EmailTransmissionReceipt;
  raw_mime_headers?: string;
  logs?: string[];
}

export interface AnalysisResponse {
  success: boolean;
  case_id?: string;
  file: FileMetadata;
  cryptographic_verification?: CryptographicVerificationInfo;
  certificate_analysis?: CertificateAnalysisInfo;
  stateful_replay?: StatefulReplayInfo;
  security?: {
    file_integrity?: string;
    sha256: string;
    integrity_status: string;
    modification_indicators: string;
    overall_security_status: string;
  };
  signature: DigitalSignatureInfo;
  threat: ThreatResult;
  quantum: QuantumMetrics;
  post_quantum_assessment?: PostQuantumAssessment;
  cbom?: CBOMData;
  attack_table: AttackTableRow[];
  logs: SecurityLog[];
  forensic_summary?: ForensicSummary;
  email_alert?: EmailAlertStatus;
  report_files?: {
    pdf_url: string;
    txt_url: string;
    pdf_filename: string;
    txt_filename: string;
  };
  content_preview: {
    raw_text: string;
    line_count: number;
    extracted_type: string;
    structured_fields?: Record<string, string>;
    warning?: string;
  };
  summary: {
    case_id?: string;
    analyzed_at: string;
    overall_status: string;
    primary_threat: string;
    threat_category?: string;
    risk_score: number;
    risk_level: string;
    recommendation_summary: string;
    pqc_migration_target?: string;
    email_dispatched?: boolean;
    email_recipient?: string;
  };
  graphs: {
    labels: string[];
    values: number[];
    quantum_labels: string[];
    quantum_values: number[];
  };
}
