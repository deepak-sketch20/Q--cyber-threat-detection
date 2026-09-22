/**
 * TypeScript Unit Tests for Adaptive Statistical Threshold module (src/adaptiveThreshold.ts)
 * 
 * Verifies:
 * 1. Genuine Signer (Normal operational bounds)
 * 2. Forgery Scenario
 * 3. Impersonation Scenario
 * 4. Replay Scenario
 * 5. Quantum Channel Manipulation Scenario
 * 6. Edge cases: Insufficient samples (<2), zero variance, domain clamping [0, 100]%
 */

import {
  calculateAdaptiveThreshold,
  deriveCandidateMeasurement,
  generateGenuineSimulationMeasurements
} from './adaptiveThreshold';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`FAILED: ${message}`);
    process.exit(1);
  }
}

function runTypeScriptTests() {
  console.log('==================================================');
  console.log('RUNNING TS ADAPTIVE THRESHOLD UNIT TESTS');
  console.log('==================================================');

  let passed = 0;
  let total = 0;

  // 1. Genuine Signer (Real QDS Simulation Batches)
  total++;
  const genuineSamples = generateGenuineSimulationMeasurements(30, 1024);
  assert(genuineSamples.length === 30, 'Should generate 30 genuine simulation batches');

  const genuineMeas = deriveCandidateMeasurement('Normal', 'Signature Status: VALID');
  const resGenuine = calculateAdaptiveThreshold(genuineSamples, genuineMeas);

  console.log(`\n[Test 1] Genuine Signer:`);
  console.log(`  Sample Count: ${resGenuine.sampleCount}`);
  console.log(`  Mean: ${resGenuine.mean.toFixed(2)}%, StdDev: ${resGenuine.standardDeviation.toFixed(2)}%`);
  console.log(`  Bounds: [${resGenuine.lowerThreshold.toFixed(2)}% - ${resGenuine.upperThreshold.toFixed(2)}%]`);
  console.log(`  Candidate: ${resGenuine.currentMeasurement.toFixed(2)}%`);
  console.log(`  Status: ${resGenuine.status}`);

  assert(resGenuine.isWithinRange === true, 'Genuine signer should be within normal range');
  assert(resGenuine.statisticalAnomaly === false, 'Genuine signer should not be flagged as anomaly');
  assert(resGenuine.sampleCount === 30, 'Sample count must match');
  passed++;
  console.log('  PASS');

  // 2. Forgery Scenario
  total++;
  const forgeryMeas = deriveCandidateMeasurement('Forgery', 'Signature Status: INVALID; Hash Mismatch: TRUE');
  const resForgery = calculateAdaptiveThreshold(genuineSamples, forgeryMeas);

  console.log(`\n[Test 2] Forgery Attack Scenario:`);
  console.log(`  Candidate: ${resForgery.currentMeasurement.toFixed(2)}%`);
  console.log(`  Anomaly: ${resForgery.statisticalAnomaly}`);
  console.log(`  Status: ${resForgery.status}`);

  assert(resForgery.isWithinRange === false, 'Forgery measurement should be outside range');
  assert(resForgery.statisticalAnomaly === true, 'Forgery must trigger statistical anomaly');
  passed++;
  console.log('  PASS');

  // 3. Impersonation Scenario
  total++;
  const impMeas = deriveCandidateMeasurement('Impersonation', 'Signer: Rogue Entity; Authentication: FAILED');
  const resImp = calculateAdaptiveThreshold(genuineSamples, impMeas);

  console.log(`\n[Test 3] Impersonation Attack Scenario:`);
  console.log(`  Candidate: ${resImp.currentMeasurement.toFixed(2)}%`);
  console.log(`  Anomaly: ${resImp.statisticalAnomaly}`);

  assert(resImp.statisticalAnomaly === true, 'Impersonation must trigger statistical anomaly');
  passed++;
  console.log('  PASS');

  // 4. Replay Scenario
  total++;
  const replayMeas = deriveCandidateMeasurement('Replay', 'Nonce: REUSED; Session ID: REUSED');
  const resReplay = calculateAdaptiveThreshold(genuineSamples, replayMeas);

  console.log(`\n[Test 4] Replay Attack Scenario:`);
  console.log(`  Candidate: ${resReplay.currentMeasurement.toFixed(2)}%`);
  console.log(`  Anomaly: ${resReplay.statisticalAnomaly}`);
  passed++;
  console.log('  PASS');

  // 5. Quantum Channel Manipulation Scenario
  total++;
  const qMeas = deriveCandidateMeasurement('Quantum Channel Manipulation', 'QBER: 0.1920');
  const resQ = calculateAdaptiveThreshold(genuineSamples, qMeas);

  console.log(`\n[Test 5] Quantum Channel Manipulation Scenario:`);
  console.log(`  Candidate: ${resQ.currentMeasurement.toFixed(2)}%`);
  console.log(`  Anomaly: ${resQ.statisticalAnomaly}`);

  assert(resQ.statisticalAnomaly === true, 'Quantum channel manipulation must trigger anomaly');
  passed++;
  console.log('  PASS');

  // 6. Edge Case: Insufficient Samples (< 2)
  total++;
  const resEmpty = calculateAdaptiveThreshold([], 50.0);
  assert(resEmpty.insufficientData === true, 'Empty sample list should flag insufficient data');
  assert(resEmpty.status.includes('Insufficient Genuine Samples'), 'Status should state insufficient data');

  const resSingle = calculateAdaptiveThreshold([51.5], 50.0);
  assert(resSingle.insufficientData === true, 'Single sample should flag insufficient data');
  assert(resSingle.sampleCount === 1, 'Sample count should be 1');
  passed++;
  console.log('\n[Test 6] Edge Case: Insufficient Samples (< 2): PASS');

  // 7. Edge Case: Zero Variance
  total++;
  const zeroVarSamples = [50.0, 50.0, 50.0, 50.0];
  const resZeroVar = calculateAdaptiveThreshold(zeroVarSamples, 50.0);
  assert(resZeroVar.standardDeviation === 0.0, 'Std dev of identical samples must be 0.0');
  assert(resZeroVar.isWithinRange === true, 'Exact match in zero variance must be within range');

  const resZeroVarAnomaly = calculateAdaptiveThreshold(zeroVarSamples, 50.02);
  assert(resZeroVarAnomaly.statisticalAnomaly === true, 'Deviation in zero variance must flag anomaly');
  passed++;
  console.log('\n[Test 7] Edge Case: Zero Variance: PASS');

  // 8. Edge Case: Clamped Domain [0%, 100%]
  total++;
  const lowSamples = [0.8, 1.2, 0.9, 1.1];
  const resLow = calculateAdaptiveThreshold(lowSamples, 1.0);
  assert(resLow.lowerThreshold >= 0.0, 'Lower threshold must be clamped >= 0.0%');

  const highSamples = [98.8, 99.2, 99.0, 99.4];
  const resHigh = calculateAdaptiveThreshold(highSamples, 99.0);
  assert(resHigh.upperThreshold <= 100.0, 'Upper threshold must be clamped <= 100.0%');
  passed++;
  console.log('\n[Test 8] Edge Case: Domain Clamping [0, 100]%: PASS');

  console.log('\n==================================================');
  console.log(`ALL ${passed}/${total} TYPESCRIPT UNIT TESTS PASSED!`);
  console.log('==================================================');
}

runTypeScriptTests();
