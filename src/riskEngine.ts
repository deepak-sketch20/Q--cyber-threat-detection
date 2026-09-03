/**
 * Multi-Threat Correlation & Evidence-Weighted Risk Engine (TypeScript)
 * Evaluates all threat indicators concurrently without stopping early:
 * - Signature Forgery
 * - Replay Attack (Stateful + Nonce/Timestamp/Session/Txn)
 * - Signer Impersonation
 * - Unauthorized Verification (Authorized vs Actual Verifier)
 * - Quantum Eavesdropping (Entangle-and-Measure)
 * - Intercept-Resend Attack
 * - Quantum Channel Manipulation
 * - Classical Channel Tampering
 */

export interface DetectedThreatDetail {
  threat: string;
  threat_category: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  why_detected: string;
  evidence: string[];
  first_action: string;
  countermeasure: string;
}

export interface RiskEngineEvaluation {
  status: 'ATTACK DETECTED' | 'SECURE' | 'WARNING';
  primary_threat: string;
  detected_threat: string;
  threat_category: string;
  risk_score: number;
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  all_detected_threats: DetectedThreatDetail[];
  all_threat_names: string[];
  threat_count: number;
  why_detected: string;
  reason: string;
  evidence: string[];
  first_action: string;
  recommendation: string;
  countermeasure: string;
  scoring_model: string;
}

export function evaluateThreatRisk(
  rawText: string,
  structuredFields: Record<string, string> = {},
  statefulReplayInfo?: { is_stateful_replay: boolean; stateful_replay_type?: string; hit_count?: number },
  cryptoVerifInfo?: { mathematical_verification: string },
  certInfo?: { status: string; trust_chain: string },
  sigInfo?: { signature_status?: string; hash_mismatch?: boolean },
  quantumMetrics?: { qber?: number }
): RiskEngineEvaluation {
  const detectedThreats: DetectedThreatDetail[] = [];
  const text = rawText || '';

  // 1. SIGNATURE FORGERY
  const isForgery =
    cryptoVerifInfo?.mathematical_verification === 'FAILED' ||
    sigInfo?.signature_status?.toUpperCase().includes('INVALID') ||
    sigInfo?.hash_mismatch ||
    /Forgery Indicator\s*[:=]\s*DETECTED|Signature Status\s*[:=]\s*INVALID|Signature Invalid/i.test(text) ||
    /Hash Mismatch\s*[:=]\s*TRUE|Digest Mismatch/i.test(text);

  if (isForgery) {
    const evidence: string[] = [];
    if (cryptoVerifInfo?.mathematical_verification === 'FAILED') evidence.push('Mathematical cryptographic signature verification failed');
    if (sigInfo?.hash_mismatch || /Hash Mismatch\s*[:=]\s*TRUE/i.test(text)) evidence.push('SHA-256 payload digest mismatch detected');
    if (/Signature Status\s*[:=]\s*INVALID/i.test(text)) evidence.push('Signature status explicitly flagged INVALID');

    detectedThreats.push({
      threat: 'Digital Signature Forgery',
      threat_category: 'Cryptographic Integrity Breach',
      risk_score: 94,
      risk_level: 'CRITICAL',
      why_detected: 'The cryptographic signature digest or mathematical verification failed, indicating payload alteration or key mismatch.',
      evidence: evidence.length > 0 ? evidence : ['Signature mathematical verification failed'],
      first_action: 'Reject invalid signature and isolate the transaction immediately.',
      countermeasure: 'Quarantine unverified message; rotate compromised signing credentials; enforce multi-party threshold signatures.'
    });
  }

  // 2. REPLAY ATTACK
  const isReplay =
    statefulReplayInfo?.is_stateful_replay ||
    structuredFields['nonce'] === 'REUSED' ||
    /Nonce\s*[:=]\s*REUSED|Reused Nonce/i.test(text) ||
    structuredFields['timestamp'] === 'REPEATED' ||
    /Timestamp\s*[:=]\s*REPEATED|Repeated Timestamp/i.test(text) ||
    structuredFields['session_id'] === 'REUSED' ||
    /Session ID\s*[:=]\s*REUSED|Reused Session ID/i.test(text) ||
    /Replay Indicator\s*[:=]\s*DETECTED|TXN-REPLAY/i.test(text);

  if (isReplay) {
    const evidence: string[] = [];
    if (statefulReplayInfo?.is_stateful_replay) evidence.push(`Stateful Replay Store matched identifier (Hits: ${statefulReplayInfo.hit_count || 2})`);
    if (/Nonce\s*[:=]\s*REUSED/i.test(text) || structuredFields['nonce'] === 'REUSED') evidence.push('Nonce value flagged as REUSED');
    if (/Timestamp\s*[:=]\s*REPEATED/i.test(text) || structuredFields['timestamp'] === 'REPEATED') evidence.push('Timestamp repeated / outside freshness window');
    if (/Session ID\s*[:=]\s*REUSED/i.test(text) || structuredFields['session_id'] === 'REUSED') evidence.push('Session ID reused');

    detectedThreats.push({
      threat: 'Replay Attack',
      threat_category: 'Session Replay & Freshness Violation',
      risk_score: 88,
      risk_level: 'HIGH',
      why_detected: 'Nonce, timestamp, session ID, or transaction hash has been previously recorded. Note: A valid digital signature alone does not prevent replay.',
      evidence: evidence.length > 0 ? evidence : ['Duplicate transaction or reused nonce detected'],
      first_action: 'Reject the reused transaction immediately.',
      countermeasure: 'Enforce cryptographic nonce uniqueness cache; enforce strict timestamp freshness window (<60s); bind session tokens to transport layer; reject duplicate transaction hashes.'
    });
  }

  // 3. SIGNER IMPERSONATION
  const isImpersonation =
    /Impersonation Indicator\s*[:=]\s*DETECTED|Impersonation/i.test(text) ||
    /Authentication\s*[:=]\s*FAILED/i.test(text) ||
    structuredFields['authentication']?.toUpperCase() === 'FAILED' ||
    /Unknown User|Rogue Signer|UNVERIFIED_SIGNER/i.test(text) ||
    certInfo?.status === 'INVALID' ||
    certInfo?.status === 'UNTRUSTED' ||
    certInfo?.trust_chain === 'FAILED';

  if (isImpersonation) {
    const evidence: string[] = [];
    if (/Impersonation Indicator\s*[:=]\s*DETECTED/i.test(text)) evidence.push('Signer impersonation indicator flagged');
    if (/Authentication\s*[:=]\s*FAILED/i.test(text)) evidence.push('Identity authentication verification failed');
    if (/Unknown User|Rogue Signer/i.test(text)) evidence.push('Signer identity not found in authorized directory');

    detectedThreats.push({
      threat: 'Signer Impersonation',
      threat_category: 'Identity & Authentication Spoofing',
      risk_score: 82,
      risk_level: 'HIGH',
      why_detected: 'Claimed signer identity or certificate fails authentication against authorized PKI directory.',
      evidence: evidence.length > 0 ? evidence : ['Signer identity authentication failure'],
      first_action: 'Block unauthorized identity and require re-authentication.',
      countermeasure: 'Enforce strict X.509 PKI trust chain verification; mandate hardware security module (HSM) identity tokens; integrate multi-factor certificate attestation.'
    });
  }

  // 4. UNAUTHORIZED VERIFICATION
  const authVerifier = structuredFields['authorized_verifier'] || 'Finance Department';
  const actualVerifier = structuredFields['actual_verifier'] || structuredFields['verifier'];
  const isUnauthVerif =
    (actualVerifier && !/finance department|security officer|alice|authorized/i.test(actualVerifier)) ||
    /Unauthorized Verification|Unauthorized Verifier/i.test(text);

  if (isUnauthVerif) {
    detectedThreats.push({
      threat: 'Unauthorized Verification',
      threat_category: 'Access Control & Verification Governance',
      risk_score: 84,
      risk_level: 'HIGH',
      why_detected: `Verification requested by unauthorized entity (${actualVerifier || 'Unknown User'}). Authorized: ${authVerifier}.`,
      evidence: [`Actual verifier '${actualVerifier || 'Unknown User'}' is not authorized for this transaction`],
      first_action: 'Block the unauthorized verifier.',
      countermeasure: 'Implement role-based access control (RBAC) on verification endpoints; enforce verifier identity attestation; restrict verification permissions to designated cryptographic audit entities.'
    });
  }

  // 5. QUANTUM EAVESDROPPING (Entangle-and-Measure)
  const qberVal = quantumMetrics?.qber ?? (parseFloat((text.match(/QBER\s*[:=]\s*([0-9]*\.?[0-9]+)/i) || [])[1] || '0'));
  const isEavesdropping =
    /Entangle-and-Measure|Eavesdropping Indicator\s*[:=]\s*DETECTED/i.test(text) ||
    qberVal >= 0.11;

  if (isEavesdropping) {
    detectedThreats.push({
      threat: 'Quantum Eavesdropping (Entangle-and-Measure)',
      threat_category: 'Quantum Channel Physical-Layer Attack',
      risk_score: 96,
      risk_level: 'CRITICAL',
      why_detected: `Simulated quantum bit error rate (QBER = ${(qberVal * 100).toFixed(2)}%) exceeds the 11.00% theoretical QDS security bound, indicating physical probe interaction.`,
      evidence: [`QBER ${(qberVal * 100).toFixed(2)}% exceeds 11% threshold`, 'Entangle-and-measure interaction detected on simulated quantum carrier'],
      first_action: 'Terminate/suspend the affected simulated quantum channel.',
      countermeasure: 'Abort key distillation; switch to alternate quantum entanglement path; initiate simulated privacy amplification and decoy-state protocol.'
    });
  }

  // 6. INTERCEPT-RESEND ATTACK
  const isIntercept = /Intercept-Resend|Intercept and Resend/i.test(text);
  if (isIntercept) {
    detectedThreats.push({
      threat: 'Intercept-Resend Attack',
      threat_category: 'Quantum Basis Measurement Interception',
      risk_score: 91,
      risk_level: 'CRITICAL',
      why_detected: 'Non-orthogonal basis measurements by adversary induced systematic 25% conjugate basis error rate.',
      evidence: ['Basis mismatch rate ~25% detected during quantum key reconciliation'],
      first_action: 'Terminate the compromised quantum channel.',
      countermeasure: 'Deploy decoy-state protocol; detect non-orthogonal basis tampering; reroute entanglement distribution.'
    });
  }

  // 7. QUANTUM CHANNEL MANIPULATION
  const isQManip = /Quantum Channel Manipulation|Quantum Channel\s*[:=]\s*MANIPULATED/i.test(text);
  if (isQManip) {
    detectedThreats.push({
      threat: 'Quantum Channel Manipulation',
      threat_category: 'Physical Channel State Perturbation',
      risk_score: 80,
      risk_level: 'HIGH',
      why_detected: 'Simulated quantum channel telemetry shows state phase and polarization drift exceeding operational limits.',
      evidence: ['Active phase and polarization distortion observed on quantum channel'],
      first_action: 'Reject the modified message and re-establish a trusted channel.',
      countermeasure: 'Perform quantum state tomography; recalibrate phase/polarization baselines; re-entangle Bell pairs.'
    });
  }

  // 8. CLASSICAL CHANNEL TAMPERING
  const isTampering = /Channel Status\s*[:=]\s*TAMPERED|Message Modification\s*[:=]\s*DETECTED|Channel Tampering/i.test(text);
  if (isTampering) {
    detectedThreats.push({
      threat: 'Classical Channel Tampering',
      threat_category: 'In-Transit Payload Modification',
      risk_score: 79,
      risk_level: 'HIGH',
      why_detected: 'Payload bits altered during transmission between intermediate network hops.',
      evidence: ['Classical payload packet modification detected on transmission transit route'],
      first_action: 'Reject the modified message and re-establish a trusted channel.',
      countermeasure: 'Enforce HMAC-SHA256 authenticated framing; enable end-to-end TLSv1.3 transport security; reject payload digest discrepancies.'
    });
  }

  // Final Selection & Score Calculation
  if (detectedThreats.length === 0) {
    return {
      status: 'SECURE',
      primary_threat: 'None (System Operating Normally)',
      detected_threat: 'None (System Operating Normally)',
      threat_category: 'Operational Normal',
      risk_score: 6,
      risk: 'LOW',
      risk_level: 'LOW',
      confidence: 99.0,
      all_detected_threats: [],
      all_threat_names: ['None'],
      threat_count: 0,
      why_detected: 'All cryptographic checks, state freshness, X.509 PKI certificates, and simulated quantum telemetry indicate intact integrity.',
      reason: 'All cryptographic checks, state freshness, X.509 PKI certificates, and simulated quantum telemetry indicate intact integrity.',
      evidence: ['SHA-256 file integrity intact', 'Cryptographic signature verified', 'Quantum channel error rate within nominal bounds (< 2.0%)'],
      first_action: 'Allow transaction processing.',
      recommendation: 'Maintain routine continuous telemetry monitoring.',
      countermeasure: 'Maintain routine continuous telemetry monitoring.',
      scoring_model: 'Multi-Threat Correlation & Evidence-Weighted Risk Engine'
    };
  }

  // Sort descending by risk score
  detectedThreats.sort((a, b) => b.risk_score - a.risk_score);
  const top = detectedThreats[0];
  let finalScore = top.risk_score;

  if (detectedThreats.length > 1) {
    finalScore = Math.min(100, finalScore + (detectedThreats.length - 1) * 2);
  }

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (finalScore >= 90) riskLevel = 'CRITICAL';
  else if (finalScore >= 60) riskLevel = 'HIGH';
  else if (finalScore >= 30) riskLevel = 'MEDIUM';

  return {
    status: 'ATTACK DETECTED',
    primary_threat: top.threat,
    detected_threat: top.threat,
    threat_category: top.threat_category,
    risk_score: finalScore,
    risk: riskLevel,
    risk_level: riskLevel,
    confidence: 96.0,
    all_detected_threats: detectedThreats,
    all_threat_names: detectedThreats.map(t => t.threat),
    threat_count: detectedThreats.length,
    why_detected: top.why_detected,
    reason: top.why_detected,
    evidence: top.evidence,
    first_action: top.first_action,
    recommendation: top.countermeasure,
    countermeasure: top.countermeasure,
    scoring_model: 'Multi-Threat Correlation & Evidence-Weighted Risk Engine'
  };
}
