# QUANTUM DIGITAL SIGNATURE SECURITY ANALYZER

> **A Simulation-Based Quantum Digital Signature (QDS) Security Framework & Threat Intelligence Platform**  
> Incorporating Bell-State Entanglement, Quantum Teleportation, Pauli Unitary Corrections, Projective Measurements, QBER Statistical Analysis, and Post-Quantum Cryptography (PQC).

---

## 🌟 Executive Solution Statement

> *"We propose a simulation-based Quantum Digital Signature (QDS) security framework that uses Bell-state entanglement, quantum teleportation, Pauli corrections, projective measurements, and statistical analysis to detect forgery, impersonation, replay, unauthorized verification, and quantum-channel manipulation attacks."*

---

## 🔬 Core Quantum & Cryptographic Modules

### 1. Quantum State & Qubit Laboratory
- **Statevector Formulation**: Supports computational ground basis $|0\rangle$, excited state $|1\rangle$, equal superposition $|+\rangle = \frac{|0\rangle + |1\rangle}{\sqrt{2}}$, phase state $|-\rangle = \frac{|0\rangle - |1\rangle}{\sqrt{2}}$, and arbitrary Bloch sphere rotations parameterized by polar angle $\theta$ and azimuth $\phi$:
  $$|\psi\rangle = \cos(\theta/2)|0\rangle + e^{i\phi}\sin(\theta/2)|1\rangle$$
- **Hadamard Transform**: Creates uniform quantum superposition from pure deterministic states.
- **Born Rule Probabilities**: Calculates $P(0) = |\alpha|^2$ and $P(1) = |\beta|^2$, verified across simulated statistical measurement shots.

### 2. Bell-State Generator & Entanglement Engine
- **Maximally Entangled 2-Qubit Bell Basis**:
  - $|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$
  - $|\Phi^-\rangle = \frac{1}{\sqrt{2}}(|00\rangle - |11\rangle)$
  - $|\Psi^+\rangle = \frac{1}{\sqrt{2}}(|01\rangle + |10\rangle)$
  - $|\Psi^-\rangle = \frac{1}{\sqrt{2}}(|01\rangle - |10\rangle)$
- **Entanglement Verification**: Quantifies correlation rates between distributed pairs (e.g. Alice & Bob) under environmental decoherence and channel noise.

### 3. Quantum Teleportation Protocol & Pauli Corrections
- **Protocol Workflow**:
  1. Alice prepares signature message qubit $|\psi\rangle = \alpha|0\rangle + \beta|1\rangle$.
  2. Entangled Bell pair $(q_1, q_2)$ is distributed between Alice and Bob.
  3. Alice executes a joint Bell measurement on $(q_0, q_1)$, collapsing her state into 2 classical bits $(b_0, b_1)$.
  4. Alice transmits $(b_0, b_1)$ over an authenticated classical channel to Bob.
  5. Bob looks up the classical bit pair and applies the corresponding unitary Pauli gate to reconstruct $|\psi\rangle$ with **100% fidelity**:
     - `00` $\rightarrow$ Identity gate $I = \begin{pmatrix}1 & 0 \\ 0 & 1\end{pmatrix}$
     - `01` $\rightarrow$ Pauli-X gate $X = \begin{pmatrix}0 & 1 \\ 1 & 0\end{pmatrix}$
     - `10` $\rightarrow$ Pauli-Z gate $Z = \begin{pmatrix}1 & 0 \\ 0 & -1\end{pmatrix}$
     - `11` $\rightarrow$ Pauli-XZ gate $XZ = iY = \begin{pmatrix}0 & -1 \\ 1 & 0\end{pmatrix}$
- *Scientific Clarification*: Quantum teleportation transfers quantum-state information using entanglement and classical communication (matter is not transported).

### 4. Quantum Channel Security & QBER Assessment
- **Quantum Bit Error Rate (QBER)**:
  $$\text{QBER} = \frac{\text{Number of Mismatched Bits}}{\text{Total Compared Bits}} \times 100\%$$
- **Security Threshold Bounds**:
  - $\text{QBER} < 5.0\%$: **SECURE** — Normal physical baseline noise.
  - $5.0\% \le \text{QBER} < 11.0\%$: **SUSPICIOUS** — Elevated disturbance / potential weak eavesdropping.
  - $\text{QBER} \ge 11.0\%$: **COMPROMISED** — Theoretical quantum digital signature security threshold breached.
- **Adversarial Modes Simulated**:
  - `Normal Channel`: Clean transmission with minimal background noise ($\sim 0.8\%$).
  - `Quantum Eavesdropping`: Entangle-and-measure interception ($\sim 45.2\%$ QBER).
  - `Intercept-Resend Attack`: Projective basis collapse ($\sim 24.8\%$ QBER).
  - `Quantum Channel Manipulation`: Phase and state perturbation ($\sim 32.1\%$ QBER).

### 5. Multi-Threat Evidence Correlation & Risk Engine
- Mathematical weighted evaluation across 8 critical threat vectors:
  1. Digital Signature Forgery (Weight: 35)
  2. Replay Attacks (Weight: 25)
  3. Signer Impersonation (Weight: 30)
  4. Unauthorized Verification (Weight: 20)
  5. Quantum Eavesdropping (Weight: 35)
  6. Intercept-Resend Attacks (Weight: 30)
  7. Quantum Channel Manipulation (Weight: 25)
  8. Classical Channel Tampering (Weight: 20)
- Risk Score: Normalized on a 0–100 scale:
  - 0–29: `LOW` (Clean / Trusted)
  - 30–59: `MEDIUM` (Warning / Suspicious)
  - 60–84: `HIGH` (Threat Detected)
  - 85–100: `CRITICAL` (Immediate Quarantine)

---

## 🛠️ Technology Stack

- **Backend Logic**: Python 3.10+ (Flask, NumPy, Qiskit-equivalent statevector mathematical simulation)
- **Frontend & Dashboard**: React 18, TypeScript, Tailwind CSS, Lucide Icons, Chart.js
- **Server Gateway**: Node.js & Express (Port 3000 proxying with Vite middleware)
- **PQC Standards**: NIST FIPS 204 (ML-DSA / Dilithium) and CycloneDX Cryptographic Bill of Materials (CBOM)

---

## 🚀 Installation & Local Execution

### Option A: Running with Node / React Full-Stack (Default)
```bash
# Install dependencies
npm install

# Start development server on port 3000
npm run dev
```

### Option B: Running the Standalone Python Flask Prototype
```bash
# Install Python dependencies
pip install -r requirements.txt

# Start Flask API server
python app.py
```
Open `http://localhost:5000` (or `http://localhost:3000`) in your web browser.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/api/upload` | `POST` | Ingest and analyze digital signature / file security |
| `/api/qds/qubit` | `GET` | Qubit statevector and measurement simulation |
| `/api/qds/bell` | `GET` | 4-state Bell basis preparation & distribution |
| `/api/qds/entanglement` | `GET` | Entanglement correlation & noise verification |
| `/api/qds/teleportation` | `POST` | 3-qubit quantum teleportation & Pauli correction |
| `/api/qds/pauli` | `POST` | Pauli correction lookup for classical bits |
| `/api/qds/channel` | `POST` | Quantum channel security & adversarial attack test |
| `/api/qds/simulate` | `POST` | Complete end-to-end QDS pipeline execution |
| `/api/email/dispatch` | `POST` | Live forensic email alert trigger |
| `/api/report/download/:caseId`| `GET` | Export Executive Forensic PDF/TXT report |

---

## 📜 Notice & Compliance
- **Simulation Environment**: All quantum operations are executed via deterministic and stochastic statevector models mathematically equivalent to Qiskit Aer simulations. Operations are performed on classical processors without physical quantum hardware.
- **Machine Learning Disclaimer**: This framework uses mathematical, cryptographic, rule-based, and quantum information-theoretic algorithms — no machine learning or black-box neural networks are used.
