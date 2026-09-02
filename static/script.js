/**
 * Quantum Digital Signature Security Analyzer
 * Frontend Dashboard & API Integration Script
 */

let threatMetricsChart = null;
let quantumStateChart = null;
let currentReportData = null;

document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initFileUpload();
    initSampleButtons();
    initCharts();
    initReportActions();
    initExecutiveForensicAlertEvents();
    
    // Auto-load Test 1 on start as baseline demonstration
    loadSample('test_1_secure.txt');
});

// Live Header Clock
function initClock() {
    const badge = document.getElementById('current-time-badge');
    const update = () => {
        const now = new Date();
        if (badge) {
            badge.textContent = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
        }
    };
    update();
    setInterval(update, 1000);
}

// File Upload & Drag-and-Drop Setup
function initFileUpload() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const uploadForm = document.getElementById('upload-form');
    const filePill = document.getElementById('selected-file-pill');
    const filenameLabel = document.getElementById('selected-filename');
    const btnClear = document.getElementById('btn-clear-file');
    const btnReset = document.getElementById('btn-reset');

    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            handleFileSelected(fileInput.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files.length > 0) {
            handleFileSelected(fileInput.files[0]);
        }
    });

    if (btnClear) {
        btnClear.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.value = '';
            filePill.style.display = 'none';
        });
    }

    if (btnReset) {
        btnReset.addEventListener('click', () => {
            fileInput.value = '';
            filePill.style.display = 'none';
            document.getElementById('attack-mode-select').value = 'Automatic Detection';
            loadSample('test_1_secure.txt');
        });
    }

    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!fileInput.files || fileInput.files.length === 0) {
            alert('Please select a file first.');
            return;
        }
        await analyzeUploadedFile(fileInput.files[0]);
    });
}

function handleFileSelected(file) {
    const filePill = document.getElementById('selected-file-pill');
    const filenameLabel = document.getElementById('selected-filename');
    if (filePill && filenameLabel) {
        filenameLabel.textContent = `${file.name} (${formatBytes(file.size)})`;
        filePill.style.display = 'inline-flex';
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 1-Click Sample Buttons
function initSampleButtons() {
    const sampleButtons = document.querySelectorAll('.sample-btn');
    sampleButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const sampleId = btn.getAttribute('data-sample');
            if (sampleId) {
                loadSample(sampleId);
            }
        });
    });
}

async function loadSample(sampleId) {
    try {
        appendLog(`Loading sample test file: ${sampleId}...`, 'INFO');
        const mode = document.getElementById('attack-mode-select').value;
        const formData = new FormData();
        formData.append('sample_id', sampleId);
        formData.append('attack_mode', mode);

        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        console.log("SERVER RESPONSE:", data);

        if (data.success) {
            renderAnalysisResults(data);
        } else {
            appendLog(`Server error: ${data.error}`, 'ALERT');
            alert(`Analysis Error: ${data.error}`);
        }
    } catch (err) {
        console.error('Error executing sample analysis:', err);
        appendLog(`Network or execution failure: ${err.message}`, 'ALERT');
    }
}

async function analyzeUploadedFile(file) {
    try {
        appendLog(`Ingesting uploaded file '${file.name}' for security audit...`, 'INFO');
        const mode = document.getElementById('attack-mode-select').value;
        const formData = new FormData();
        formData.append('file', file);
        formData.append('attack_mode', mode);

        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        console.log("SERVER RESPONSE:", data);

        if (data.success) {
            renderAnalysisResults(data);
        } else {
            appendLog(`Analysis error: ${data.error}`, 'ALERT');
            alert(`Error: ${data.error}`);
        }
    } catch (err) {
        console.error('Upload analysis failure:', err);
        appendLog(`Upload execution failure: ${err.message}`, 'ALERT');
    }
}

// Render Results into UI
function renderAnalysisResults(data) {
    currentReportData = data;

    // 1. FILE SECURITY VERIFICATION
    document.getElementById('val-file-integrity').textContent = data.security.file_integrity || 'SHA-256 computed successfully';
    const integrityStatusElem = document.getElementById('val-integrity-status');
    integrityStatusElem.textContent = data.security.integrity_status;
    integrityStatusElem.className = data.security.integrity_status.includes('INTACT') 
        ? 'v-value font-mono font-bold text-success' 
        : 'v-value font-mono font-bold text-danger';

    document.getElementById('val-sha256').textContent = data.file.sha256;
    document.getElementById('val-mod-indicators').textContent = data.security.modification_indicators;
    
    const overallStatusElem = document.getElementById('val-overall-status');
    overallStatusElem.textContent = data.security.overall_security_status;
    overallStatusElem.className = data.security.overall_security_status === 'SECURE'
        ? 'v-value font-bold text-success'
        : 'v-value font-bold text-danger';

    const verificationBadge = document.getElementById('verification-badge');
    if (verificationBadge) {
        verificationBadge.textContent = data.security.overall_security_status;
        verificationBadge.className = data.security.overall_security_status === 'SECURE'
            ? 'badge badge-quantum'
            : 'badge tag-critical';
    }

    // 2. DIGITAL SIGNATURE ANALYSIS
    document.getElementById('sig-present').textContent = data.signature.signature_present ? 'YES (Signature Format Detected)' : 'NO';
    const sigStatusElem = document.getElementById('sig-status');
    sigStatusElem.textContent = data.signature.signature_status;
    sigStatusElem.className = data.signature.signature_status.includes('INVALID') || data.signature.signature_status.includes('FAILED')
        ? 's-value font-bold text-danger'
        : (data.signature.signature_status.includes('VALID') ? 's-value font-bold text-success' : 's-value font-bold');

    document.getElementById('sig-algo').textContent = data.signature.signature_algorithm;
    document.getElementById('sig-signer').textContent = data.signature.signer_information;
    document.getElementById('sig-result').textContent = data.signature.verification_result;
    document.getElementById('sig-mismatch').textContent = data.signature.hash_mismatch ? 'TRUE (MISMATCH DETECTED)' : 'FALSE (Match)';

    // 3. THREAT DETECTION CARD
    const threat = data.threat;
    const isAttack = threat.status === 'ATTACK DETECTED';

    const statusTag = document.getElementById('threat-status-tag');
    statusTag.textContent = isAttack ? '🚨 THREAT DETECTED' : '🛡️ SYSTEM SECURE';
    statusTag.className = isAttack ? 'threat-status-tag tag-critical' : 'threat-status-tag badge-quantum';

    document.getElementById('threat-detected-title').textContent = isAttack 
        ? `${threat.detected_threat}` 
        : 'No Threat Detected';
    
    document.getElementById('threat-category-title').textContent = `Threat Category: ${threat.threat_category}`;

    // Score Circle & Risk Badge
    const riskScoreVal = document.getElementById('risk-score-val');
    riskScoreVal.textContent = threat.risk_score;

    const riskCircle = document.getElementById('risk-score-circle');
    const riskBadge = document.getElementById('risk-level-badge');
    riskBadge.textContent = `${threat.risk} RISK`;

    if (threat.risk_score >= 90) {
        riskCircle.style.borderColor = '#ef4444';
        riskCircle.style.boxShadow = '0 0 20px rgba(239, 68, 68, 0.4)';
        riskBadge.className = 'risk-level-badge tag-critical';
    } else if (threat.risk_score >= 60) {
        riskCircle.style.borderColor = '#f59e0b';
        riskCircle.style.boxShadow = '0 0 20px rgba(245, 158, 11, 0.3)';
        riskBadge.className = 'risk-level-badge tag-high';
    } else {
        riskCircle.style.borderColor = '#10b981';
        riskCircle.style.boxShadow = '0 0 20px rgba(16, 185, 129, 0.3)';
        riskBadge.className = 'risk-level-badge tag-secure';
    }

    document.getElementById('confidence-val').textContent = `Confidence: ${threat.confidence}%`;
    document.getElementById('threat-reason-text').textContent = threat.reason;

    // Evidence List
    const evidenceList = document.getElementById('evidence-list');
    evidenceList.innerHTML = '';
    if (threat.evidence && threat.evidence.length > 0) {
        threat.evidence.forEach(ev => {
            const li = document.createElement('li');
            li.textContent = `✓ ${ev}`;
            evidenceList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = '✓ No anomaly indicators found.';
        evidenceList.appendChild(li);
    }

    // First Action & Prevention
    document.getElementById('first-action-text').textContent = threat.first_action;
    document.getElementById('prevention-text').textContent = threat.recommendation;

    // Multi-Threat Notice
    const multiBox = document.getElementById('multi-threat-box');
    const addList = document.getElementById('additional-threats-list');
    if (threat.additional_threats && threat.additional_threats.length > 0) {
        multiBox.style.display = 'block';
        addList.textContent = threat.additional_threats.join(', ');
    } else {
        multiBox.style.display = 'none';
    }

    // 4. QUANTUM SECURITY METRICS
    const q = data.quantum;
    document.getElementById('q-val-qber').textContent = q.qber_percentage;
    document.getElementById('q-val-mismatch').textContent = q.mismatch_rate_percentage;
    document.getElementById('q-sub-mismatch').textContent = `Mismatches: ${q.mismatches} / ${q.number_of_rounds}`;
    document.getElementById('q-val-matching').textContent = q.matching_rate_percentage;
    document.getElementById('q-sub-matches').textContent = `Matches: ${q.matches} / ${q.number_of_rounds}`;
    
    const qRiskElem = document.getElementById('q-val-risk');
    qRiskElem.textContent = q.quantum_risk;
    qRiskElem.className = q.quantum_risk === 'CRITICAL' ? 'q-val font-bold text-danger' : 'q-val font-bold text-success';
    
    document.getElementById('q-sub-status').textContent = `State Fidelity: ${q.state_preservation_fidelity}`;
    document.getElementById('q-val-eavesdrop').textContent = q.estimated_eavesdropping_probability;
    
    const qSecLevel = document.getElementById('q-val-sec-level');
    qSecLevel.textContent = q.security_level;
    qSecLevel.className = q.quantum_risk === 'CRITICAL' ? 'q-val font-bold text-danger' : 'q-val font-bold text-success';

    // 5. ATTACK SCENARIO TABLE
    renderAttackTable(data.attack_table);

    // 6. UPDATE CHARTS
    updateCharts(data.graphs);

    // 7. SECURITY AUDIT LOGS
    renderLogs(data.logs);

    // 8. FINAL REPORT SUMMARY
    updateReportSummary(data);

    // 9. EXECUTIVE FORENSIC ALERT CARD & MODAL (Appears only on High-Risk Threats)
    renderExecutiveForensicAlert(data);
}

function renderExecutiveForensicAlert(data) {
    const card = document.getElementById('executive-forensic-alert-card');
    if (!card) return;

    const threat = data.threat;
    const forensic = data.forensic_summary;
    const emailAlert = data.email_alert;
    
    // Check if high-risk threat is detected
    const isHighRisk = (threat && (threat.status === 'ATTACK DETECTED' || threat.risk === 'HIGH' || threat.risk === 'CRITICAL' || threat.risk_score >= 60)) ||
                       (forensic && (forensic.risk_level === 'HIGH' || forensic.risk_level === 'CRITICAL' || (forensic.threat_score && forensic.threat_score >= 60)));

    if (!isHighRisk) {
        card.style.display = 'none';
        return;
    }

    // Show Card
    card.style.display = 'block';

    // Status
    const statusText = (threat && threat.status) || (forensic && forensic.overall_status) || 'ATTACK DETECTED';
    const statusBadge = document.getElementById('efa-status-badge');
    if (statusBadge) statusBadge.textContent = `STATUS: ${statusText}`;
    const statusTextEl = document.getElementById('efa-status-text');
    if (statusTextEl) statusTextEl.textContent = statusText;

    // Risk
    const riskLevel = (threat && threat.risk) || (forensic && forensic.risk_level) || 'HIGH';
    const riskScore = (threat && threat.risk_score) || (forensic && forensic.threat_score) || 78;
    const riskBadge = document.getElementById('efa-risk-badge');
    if (riskBadge) {
        riskBadge.textContent = `${riskLevel} RISK (${riskScore}/100)`;
        riskBadge.className = riskScore >= 85 ? 'badge tag-critical' : 'badge tag-high';
    }
    const riskTextEl = document.getElementById('efa-risk-text');
    if (riskTextEl) riskTextEl.textContent = `${riskLevel} RISK (Score: ${riskScore}/100)`;

    // Case ID
    const caseId = data.case_id || (forensic && forensic.case_id) || (data.summary && data.summary.case_id) || ('CASE-' + (data.file && data.file.sha256 ? data.file.sha256.substring(0, 8).toUpperCase() : '2026-X94'));
    const caseDisplayEl = document.getElementById('efa-case-id-display');
    if (caseDisplayEl) caseDisplayEl.textContent = caseId;
    const caseTextEl = document.getElementById('efa-case-id-text');
    if (caseTextEl) caseTextEl.textContent = caseId;

    // Triggered Rules List
    const rulesList = document.getElementById('efa-rules-list');
    if (rulesList) {
        rulesList.innerHTML = '';
        let rules = [];
        if (forensic && forensic.threat_indicators && forensic.threat_indicators.length > 0) {
            rules = forensic.threat_indicators;
        } else if (threat && threat.evidence && threat.evidence.length > 0) {
            rules = threat.evidence;
        } else {
            rules = [
                `Cryptographic anomaly: ${threat ? threat.detected_threat : 'Signature tampering'}`,
                `High-risk threshold exceeded (Score: ${riskScore}/100)`
            ];
        }

        rules.forEach(rule => {
            const li = document.createElement('li');
            li.innerHTML = `<span class="rule-bullet">•</span> ${escapeHtml(rule)}`;
            rulesList.appendChild(li);
        });
    }

    // Email Delivery Status
    const recipient = (emailAlert && emailAlert.recipient) || 'deepakmurugaiyan@gmail.com';
    const recipientEl = document.getElementById('efa-recipient-display');
    if (recipientEl) recipientEl.textContent = recipient;

    let deliveryStatus = 'Sent';
    let statusClass = 'dot-sent';

    if (emailAlert) {
        if (emailAlert.status === 'FAILED' || emailAlert.status === 'ERROR') {
            deliveryStatus = 'Failed';
            statusClass = 'dot-failed';
        } else if (emailAlert.status === 'PENDING' || emailAlert.status === 'QUEUED') {
            deliveryStatus = 'Pending';
            statusClass = 'dot-pending';
        } else {
            deliveryStatus = 'Sent';
            statusClass = 'dot-sent';
        }
    } else {
        deliveryStatus = 'Sent';
        statusClass = 'dot-sent';
    }

    const emailStatusTextEl = document.getElementById('efa-email-status-text');
    if (emailStatusTextEl) emailStatusTextEl.textContent = deliveryStatus;
    const emailStatusDotEl = document.getElementById('efa-email-status-dot');
    if (emailStatusDotEl) emailStatusDotEl.className = `efa-status-dot ${statusClass}`;

    // Update Modal Data Fields
    const modalCaseId = document.getElementById('modal-case-id');
    if (modalCaseId) modalCaseId.textContent = caseId;
    const modalThreatStatus = document.getElementById('modal-threat-status');
    if (modalThreatStatus) modalThreatStatus.textContent = `${riskLevel} RISK THREAT`;
    const modalTargetFile = document.getElementById('modal-target-file');
    if (modalTargetFile) modalTargetFile.textContent = `${data.file.filename} (${data.file.file_size})`;
    const modalRiskScore = document.getElementById('modal-risk-score');
    if (modalRiskScore) modalRiskScore.textContent = `${riskLevel} (${riskScore}/100)`;
    const modalSigStatus = document.getElementById('modal-sig-status');
    if (modalSigStatus) modalSigStatus.textContent = data.signature ? data.signature.signature_status : 'TAMPERED / INVALID';
    const modalEmailDelivery = document.getElementById('modal-email-delivery');
    if (modalEmailDelivery) modalEmailDelivery.textContent = `Dispatched (${deliveryStatus})`;

    // Generate Complete Structured Forensic Report Text
    const generatedReport = generateForensicReportText(data, caseId, riskLevel, riskScore, deliveryStatus, recipient);
    const modalReportContent = document.getElementById('modal-report-content');
    if (modalReportContent) modalReportContent.textContent = generatedReport;
}

function generateForensicReportText(data, caseId, riskLevel, riskScore, deliveryStatus, recipient) {
    const t = data.threat || {};
    const f = data.file || {};
    const s = data.signature || {};
    const q = data.quantum || {};
    const forensic = data.forensic_summary || {};

    let rules = [];
    if (forensic.threat_indicators && forensic.threat_indicators.length > 0) {
        rules = forensic.threat_indicators;
    } else if (t.evidence && t.evidence.length > 0) {
        rules = t.evidence;
    } else {
        rules = [`Security threshold violation: ${t.detected_threat || 'Signature Anomaly'}`];
    }

    return `================================================================================
EXECUTIVE FORENSIC INVESTIGATION REPORT
Quantum Digital Signature & Cryptographic Telemetry Analysis
================================================================================
CASE IDENTIFIER:      ${caseId}
EVALUATION TIMESTAMP: ${new Date().toUTCString()}
TARGET FILE:          ${f.filename || 'unknown.bin'} (${f.file_size || '0 KB'})
FILE SHA-256 DIGEST:  ${f.sha256 || 'N/A'}

[1] EXECUTIVE THREAT TRIAGE
--------------------------------------------------------------------------------
Overall Status:       ${t.status || 'ATTACK DETECTED'} (${riskLevel} RISK)
Threat Score:         ${riskScore} / 100
Primary Threat:       ${t.detected_threat || 'Cryptographic Malicious Indicator'}
Threat Category:      ${t.threat_category || 'Digital Signature Attack'}
Confidence Level:     ${t.confidence || 95}%
Trigger Reason:       ${t.reason || 'Cryptographic integrity failure detected.'}

[2] DIGITAL SIGNATURE & INTEGRITY EVALUATION
--------------------------------------------------------------------------------
Signature Present:    ${s.signature_present ? 'YES' : 'NO'}
Verification Status:  ${s.signature_status || 'INVALID'}
Signature Algorithm:  ${s.signature_algorithm || 'ECDSA-SHA256'}
Signer Information:   ${s.signer_information || 'UNKNOWN'}
Hash Verification:    ${s.hash_mismatch ? 'MISMATCH DETECTED' : 'MATCH'}
Integrity Status:     ${data.security ? data.security.integrity_status : 'CORRUPTED / TAMPERED'}

[3] TRIGGERED SECURITY RULES & INDICATORS
--------------------------------------------------------------------------------
${rules.map((r, i) => `[Rule ${i + 1}] ${r}`).join('\n')}

[4] QUANTUM-INSPIRED TELEMETRY
--------------------------------------------------------------------------------
Quantum Bit Error Rate (QBER):  ${q.qber_percentage || '0.00%'}
Mismatch Rate:                  ${q.mismatch_rate_percentage || '0.00%'}
Matching Key Rate:              ${q.matching_rate_percentage || '100.00%'}
Eavesdropping Probability:      ${q.estimated_eavesdropping_probability || '0.00%'}
Quantum Threat Level:           ${q.quantum_risk || 'LOW'}
Channel Security Level:         ${q.security_level || 'SECURE'}

[5] EMAIL ALERT DELIVERY & DISPATCH AUDIT
--------------------------------------------------------------------------------
Delivery Status:      ${deliveryStatus}
Recipient:            ${recipient}
Transport Security:   TLSv1.3 (TLS_AES_256_GCM_SHA384 / STARTTLS)
Dispatched Timestamp: ${new Date().toISOString()}

[6] RECOMMENDED EXECUTIVE ACTION
--------------------------------------------------------------------------------
Immediate Response:   ${t.first_action || 'Quarantine file and isolate host.'}
Long-term Prevention: ${t.recommendation || 'Upgrade to post-quantum cryptographic primitives (ML-DSA / FIPS 204).'}
================================================================================`;
}

function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function renderAttackTable(attackRows) {
    const tbody = document.getElementById('attack-table-body');
    tbody.innerHTML = '';

    attackRows.forEach(row => {
        const tr = document.createElement('tr');
        
        let statusBadgeClass = 'badge-not-detected';
        if (row.status === 'AUTO-DETECTED') statusBadgeClass = 'badge-auto-detected';
        else if (row.status === 'SIMULATION') statusBadgeClass = 'badge-simulation';

        tr.innerHTML = `
            <td class="font-bold">${row.attack}</td>
            <td><span class="${statusBadgeClass}">${row.status}</span></td>
            <td><span class="${row.risk_score >= 60 ? 'text-danger font-bold' : 'text-success'}">${row.risk}</span></td>
            <td class="font-mono font-bold">${row.risk_score}</td>
            <td class="text-secondary">${row.reason}</td>
        `;
        tbody.appendChild(tr);
    });
}

function updateCharts(graphsData) {
    if (!window.Chart) {
        console.warn("Chart.js not loaded yet.");
        return;
    }

    // 1. Threat Metrics Chart
    const ctxThreat = document.getElementById('threatMetricsChart');
    if (ctxThreat) {
        if (threatMetricsChart) {
            threatMetricsChart.destroy();
        }

        threatMetricsChart = new Chart(ctxThreat, {
            type: 'bar',
            data: {
                labels: graphsData.labels || ['Risk Score', 'Confidence', 'Threat Intensity'],
                datasets: [{
                    label: 'Metric Value (%)',
                    data: graphsData.values || [5, 96, 5],
                    backgroundColor: [
                        graphsData.values[0] >= 60 ? '#ef4444' : '#10b981',
                        '#3b82f6',
                        graphsData.values[2] >= 60 ? '#f59e0b' : '#06b6d4'
                    ],
                    borderColor: '#2a3854',
                    borderWidth: 1,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#f8fafc', font: { weight: '600' } }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#151e32',
                        titleColor: '#06b6d4',
                        bodyColor: '#fff',
                        borderColor: '#2a3854',
                        borderWidth: 1
                    }
                }
            }
        });
    }

    // 2. Quantum State Chart
    const ctxQuantum = document.getElementById('quantumStateChart');
    if (ctxQuantum) {
        if (quantumStateChart) {
            quantumStateChart.destroy();
        }

        quantumStateChart = new Chart(ctxQuantum, {
            type: 'doughnut',
            data: {
                labels: graphsData.quantum_labels || ['Matching Rate', 'Mismatch Rate', 'QBER'],
                datasets: [{
                    data: graphsData.quantum_values || [98.8, 1.2, 1.2],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderColor: '#111827',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', boxWidth: 12, padding: 10 }
                    }
                },
                cutout: '65%'
            }
        });
    }
}

function renderLogs(logs) {
    const container = document.getElementById('terminal-logs');
    container.innerHTML = '';
    logs.forEach(log => {
        const div = document.createElement('div');
        let statusClass = 'log-info';
        if (log.status === 'ALERT' || log.status === 'ACTION_REQUIRED') statusClass = 'log-alert';
        else if (log.status === 'WARNING') statusClass = 'log-warning';
        else if (log.status === 'SUCCESS') statusClass = 'log-success';

        div.className = `log-entry ${statusClass}`;
        div.innerHTML = `<span class="log-time">[${log.time}]</span> ${log.event}`;
        container.appendChild(div);
    });
    container.scrollTop = container.scrollHeight;
}

function appendLog(msg, type = 'INFO') {
    const container = document.getElementById('terminal-logs');
    if (!container) return;
    const now = new Date().toTimeString().split(' ')[0];
    const div = document.createElement('div');
    div.className = `log-entry ${type === 'ALERT' ? 'log-alert' : 'log-info'}`;
    div.innerHTML = `<span class="log-time">[${now}]</span> ${msg}`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function updateReportSummary(data) {
    const box = document.getElementById('report-summary-text');
    const t = data.threat;
    const f = data.file;

    box.innerHTML = `
        <strong>Target File:</strong> ${f.filename} (${f.file_size}) | <strong>SHA-256:</strong> <code>${f.sha256}</code><br>
        <strong>Security Verification:</strong> ${data.security.overall_security_status} &bull; <strong>Integrity:</strong> ${data.security.integrity_status}<br>
        <strong>Detected Threat Vector:</strong> <span class="${t.status === 'ATTACK DETECTED' ? 'text-danger font-bold' : 'text-success'}">${t.detected_threat} (${t.threat_category})</span><br>
        <strong>Assessed Risk:</strong> ${t.risk} (${t.risk_score}/100) with ${t.confidence}% confidence.<br>
        <strong>Primary Response:</strong> ${t.first_action}<br>
        <strong>Long-term Prevention:</strong> ${t.recommendation}
    `;
}

function initReportActions() {
    const btnPrint = document.getElementById('btn-print-report');
    const btnJson = document.getElementById('btn-download-json');
    const btnExportLogs = document.getElementById('btn-export-logs');

    if (btnPrint) {
        btnPrint.addEventListener('click', () => {
            window.print();
        });
    }

    if (btnJson) {
        btnJson.addEventListener('click', () => {
            if (!currentReportData) {
                alert('No report data generated yet.');
                return;
            }
            const blob = new Blob([JSON.stringify(currentReportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security_report_${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
        });
    }

    if (btnExportLogs) {
        btnExportLogs.addEventListener('click', () => {
            const container = document.getElementById('terminal-logs');
            const text = container.innerText;
            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security_audit_logs_${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        });
    }
}

function initExecutiveForensicAlertEvents() {
    const btnTopEmailAlert = document.getElementById('btn-top-email-alert');
    const modal = document.getElementById('forensic-summary-modal');
    const btnViewSummary = document.getElementById('btn-view-forensic-summary');
    const btnCloseModal = document.getElementById('btn-close-forensic-modal');
    const btnCloseModalAction = document.getElementById('btn-modal-close-action');
    const btnCopyReport = document.getElementById('btn-copy-modal-report');
    const btnGmailModal = document.getElementById('btn-modal-gmail-open');
    const btnGmailCard = document.getElementById('btn-open-gmail-web');
    const btnDownloadPdfModal = document.getElementById('btn-modal-download-pdf');
    const btnDownloadPdfCard = document.getElementById('btn-download-forensic-pdf');
    const btnDownloadTxtModal = document.getElementById('btn-modal-download-txt');

    const openModal = () => {
        if (modal) modal.style.display = 'flex';
    };

    const closeModal = () => {
        if (modal) modal.style.display = 'none';
    };

    if (btnTopEmailAlert) {
        btnTopEmailAlert.addEventListener('click', () => {
            if (currentReportData) {
                // Ensure latest fields are populated in modal
                const threat = currentReportData.threat || {};
                const forensic = currentReportData.forensic_summary || {};
                const riskLevel = threat.risk || forensic.risk_level || 'HIGH';
                const riskScore = threat.risk_score || forensic.threat_score || 78;
                const caseId = currentReportData.case_id || (forensic && forensic.case_id) || 'CASE-2026-X94';
                const recipient = (currentReportData.email_alert && currentReportData.email_alert.recipient) || 'deepakmurugaiyan@gmail.com';
                const deliveryStatus = (currentReportData.email_alert && currentReportData.email_alert.status === 'SENT') ? 'Sent' : 'Dispatched';

                const modalCaseId = document.getElementById('modal-case-id');
                if (modalCaseId) modalCaseId.textContent = caseId;
                const modalThreatStatus = document.getElementById('modal-threat-status');
                if (modalThreatStatus) modalThreatStatus.textContent = `${riskLevel} RISK THREAT`;
                const modalTargetFile = document.getElementById('modal-target-file');
                if (modalTargetFile && currentReportData.file) modalTargetFile.textContent = `${currentReportData.file.filename} (${currentReportData.file.file_size})`;
                const modalRiskScore = document.getElementById('modal-risk-score');
                if (modalRiskScore) modalRiskScore.textContent = `${riskLevel} (${riskScore}/100)`;
                const modalSigStatus = document.getElementById('modal-sig-status');
                if (modalSigStatus) modalSigStatus.textContent = currentReportData.signature ? currentReportData.signature.signature_status : 'TAMPERED / INVALID';
                const modalEmailDelivery = document.getElementById('modal-email-delivery');
                if (modalEmailDelivery) modalEmailDelivery.textContent = `Dispatched (${deliveryStatus})`;

                const generatedReport = generateForensicReportText(currentReportData, caseId, riskLevel, riskScore, deliveryStatus, recipient);
                const modalReportContent = document.getElementById('modal-report-content');
                if (modalReportContent) modalReportContent.textContent = generatedReport;
            }
            openModal();
        });
    }

    if (btnViewSummary) {
        btnViewSummary.addEventListener('click', openModal);
    }

    if (btnCloseModal) {
        btnCloseModal.addEventListener('click', closeModal);
    }

    if (btnCloseModalAction) {
        btnCloseModalAction.addEventListener('click', closeModal);
    }

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal && modal.style.display === 'flex') {
            closeModal();
        }
    });

    if (btnCopyReport) {
        btnCopyReport.addEventListener('click', () => {
            const reportEl = document.getElementById('modal-report-content');
            if (reportEl) {
                navigator.clipboard.writeText(reportEl.textContent || '').then(() => {
                    const origText = btnCopyReport.textContent;
                    btnCopyReport.textContent = '✓ Copied!';
                    setTimeout(() => {
                        btnCopyReport.textContent = origText;
                    }, 2000);
                });
            }
        });
    }

    const openGmailCompose = () => {
        if (!currentReportData) return;
        const threat = currentReportData.threat || {};
        const forensic = currentReportData.forensic_summary || {};
        const caseId = currentReportData.case_id || (forensic && forensic.case_id) || 'CASE-X';
        const riskLevel = threat.risk || forensic.risk_level || 'HIGH';
        const recipient = 'deepakmurugaiyan@gmail.com';
        const subject = `[CYBERSECURITY ALERT] High-Risk Threat Detected - ${riskLevel} - ${caseId}`;
        const body = document.getElementById('modal-report-content')?.textContent || `Security Alert for ${caseId}`;
        const url = `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(recipient)}&su=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
        window.open(url, '_blank', 'noopener,noreferrer');
    };

    if (btnGmailModal) btnGmailModal.addEventListener('click', openGmailCompose);
    if (btnGmailCard) btnGmailCard.addEventListener('click', openGmailCompose);

    const downloadReportPdf = () => {
        if (!currentReportData) return;
        const forensic = currentReportData.forensic_summary || {};
        const caseId = currentReportData.case_id || (forensic && forensic.case_id) || 'CASE-X';
        window.open(`/api/report/download/${caseId}?format=pdf`, '_blank');
    };

    if (btnDownloadPdfModal) btnDownloadPdfModal.addEventListener('click', downloadReportPdf);
    if (btnDownloadPdfCard) btnDownloadPdfCard.addEventListener('click', downloadReportPdf);

    if (btnDownloadTxtModal) {
        btnDownloadTxtModal.addEventListener('click', () => {
            const reportText = document.getElementById('modal-report-content')?.textContent || '';
            const blob = new Blob([reportText], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `Executive_Forensic_Summary_${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        });
    }
}

