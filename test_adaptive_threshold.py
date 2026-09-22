#!/usr/bin/env python3
"""
Unit tests for the Adaptive Statistical Threshold module (adaptive_threshold.py).
Covers:
1. Genuine Signer (Normal operational bounds)
2. Forgery Attack Scenario
3. Impersonation Attack Scenario
4. Replay Attack Scenario
5. Quantum Channel Manipulation Scenario
6. Edge Cases: Insufficient data (<2 samples), zero variance, clamped bounds [0%, 100%]
"""

import sys
from adaptive_threshold import (
    calculate_adaptive_threshold,
    derive_candidate_measurement,
    generate_genuine_simulation_measurements
)

def run_tests():
    passed = 0
    total = 0

    print("==================================================")
    print("RUNNING ADAPTIVE STATISTICAL THRESHOLD UNIT TESTS")
    print("==================================================")

    # 1. Genuine Signer (Real QDS Simulation Batches)
    total += 1
    genuine_samples = generate_genuine_simulation_measurements(sample_count=30, shots_per_batch=1024)
    assert len(genuine_samples) == 30, "Should generate 30 genuine simulation batches"
    
    # Genuine candidate should be close to mean
    genuine_meas = derive_candidate_measurement("Normal", "Signature Status: VALID")
    res_genuine = calculate_adaptive_threshold(genuine_samples, genuine_meas)
    
    print(f"\n[Test 1] Genuine Signer:")
    print(f"  Mean: {res_genuine['mean']:.2f}%, Std: {res_genuine['standard_deviation']:.2f}%")
    print(f"  Calibrated Range: [{res_genuine['lower_threshold']:.2f}% - {res_genuine['upper_threshold']:.2f}%]")
    print(f"  Candidate: {res_genuine['current_measurement']:.2f}%")
    print(f"  Status: {res_genuine['status']}")
    
    assert res_genuine['is_within_range'] is True, "Genuine signer should be within normal range"
    assert res_genuine['statistical_anomaly'] is False, "Genuine signer should not trigger anomaly"
    assert res_genuine['sample_count'] == 30
    passed += 1
    print("  PASS")

    # 2. Forgery Attack Scenario
    total += 1
    forgery_meas = derive_candidate_measurement("Forgery", "Signature Status: INVALID; Hash Mismatch: TRUE")
    res_forgery = calculate_adaptive_threshold(genuine_samples, forgery_meas)
    
    print(f"\n[Test 2] Forgery Attack:")
    print(f"  Candidate: {res_forgery['current_measurement']:.2f}%")
    print(f"  Anomaly: {res_forgery['statistical_anomaly']}")
    print(f"  Status: {res_forgery['status']}")
    
    assert res_forgery['is_within_range'] is False, "Forgery measurement should fall outside calibrated bounds"
    assert res_forgery['statistical_anomaly'] is True, "Forgery must trigger statistical anomaly"
    passed += 1
    print("  PASS")

    # 3. Impersonation Attack Scenario
    total += 1
    imp_meas = derive_candidate_measurement("Impersonation", "Signer: Unknown User; Authentication: FAILED")
    res_imp = calculate_adaptive_threshold(genuine_samples, imp_meas)
    
    print(f"\n[Test 3] Impersonation Attack:")
    print(f"  Candidate: {res_imp['current_measurement']:.2f}%")
    print(f"  Anomaly: {res_imp['statistical_anomaly']}")
    
    assert res_imp['statistical_anomaly'] is True, "Impersonation must trigger statistical anomaly"
    passed += 1
    print("  PASS")

    # 4. Replay Attack Scenario
    total += 1
    replay_meas = derive_candidate_measurement("Replay", "Nonce: REUSED; Session: REUSED")
    res_replay = calculate_adaptive_threshold(genuine_samples, replay_meas)
    
    print(f"\n[Test 4] Replay Attack:")
    print(f"  Candidate: {res_replay['current_measurement']:.2f}%")
    print(f"  Anomaly: {res_replay['statistical_anomaly']}")
    print("  PASS")
    passed += 1

    # 5. Quantum Channel Manipulation Scenario
    total += 1
    q_meas = derive_candidate_measurement("Quantum Channel Manipulation", "QBER: 0.1850")
    res_q = calculate_adaptive_threshold(genuine_samples, q_meas)
    
    print(f"\n[Test 5] Quantum Channel Manipulation:")
    print(f"  Candidate: {res_q['current_measurement']:.2f}%")
    print(f"  Anomaly: {res_q['statistical_anomaly']}")
    
    assert res_q['statistical_anomaly'] is True, "Manipulated quantum channel must trigger statistical anomaly"
    passed += 1
    print("  PASS")

    # 6. Edge Case: Empty and Insufficient Samples (< 2)
    total += 1
    res_insufficient_empty = calculate_adaptive_threshold([], 50.0)
    assert res_insufficient_empty['insufficient_data'] is True
    assert "Insufficient Genuine Samples" in res_insufficient_empty['status']
    
    res_insufficient_one = calculate_adaptive_threshold([51.2], 50.0)
    assert res_insufficient_one['insufficient_data'] is True
    assert res_insufficient_one['sample_count'] == 1
    passed += 1
    print("\n[Test 6] Edge Case: Insufficient Samples (< 2): PASS")

    # 7. Edge Case: Zero Variance (All identical measurements)
    total += 1
    identical_samples = [50.0] * 10
    res_zero_var = calculate_adaptive_threshold(identical_samples, 50.0)
    assert res_zero_var['standard_deviation'] == 0.0
    assert res_zero_var['is_within_range'] is True
    assert res_zero_var['lower_threshold'] == 50.0
    assert res_zero_var['upper_threshold'] == 50.0
    
    # Value slightly off with zero variance should trigger anomaly
    res_zero_var_off = calculate_adaptive_threshold(identical_samples, 50.01)
    assert res_zero_var_off['statistical_anomaly'] is True
    passed += 1
    print("\n[Test 7] Edge Case: Zero Variance: PASS")

    # 8. Edge Case: Domain Clamping [0%, 100%]
    total += 1
    low_samples = [1.0, 1.2, 0.8, 1.1]
    res_low = calculate_adaptive_threshold(low_samples, 1.0)
    assert res_low['lower_threshold'] >= 0.0, "Lower threshold must be clamped >= 0%"

    high_samples = [98.5, 99.1, 98.9, 99.4]
    res_high = calculate_adaptive_threshold(high_samples, 99.0)
    assert res_high['upper_threshold'] <= 100.0, "Upper threshold must be clamped <= 100%"
    passed += 1
    print("\n[Test 8] Edge Case: Domain Clamping [0, 100]%: PASS")

    print("\n==================================================")
    print(f"ALL {passed}/{total} ADAPTIVE THRESHOLD UNIT TESTS PASSED!")
    print("==================================================")

if __name__ == '__main__':
    run_tests()
