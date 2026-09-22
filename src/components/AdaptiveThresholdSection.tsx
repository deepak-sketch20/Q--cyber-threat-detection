import React, { useState } from 'react';
import {
  Activity,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Info,
  HelpCircle,
  BarChart2,
  Layers,
  ChevronDown,
  ChevronUp,
  RefreshCw
} from 'lucide-react';
import { AdaptiveThresholdResult } from '../types';
import { calculateAdaptiveThreshold, generateGenuineSimulationMeasurements } from '../adaptiveThreshold';

interface AdaptiveThresholdSectionProps {
  adaptiveThreshold?: AdaptiveThresholdResult;
  onRecalibrate?: (newResult: AdaptiveThresholdResult) => void;
  className?: string;
}

export const AdaptiveThresholdSection: React.FC<AdaptiveThresholdSectionProps> = ({
  adaptiveThreshold: initialThreshold,
  onRecalibrate,
  className = ''
}) => {
  const [thresholdData, setThresholdData] = useState<AdaptiveThresholdResult | undefined>(initialThreshold);
  const [showExplanation, setShowExplanation] = useState<boolean>(true);
  const [isRecalibrating, setIsRecalibrating] = useState<boolean>(false);

  // Sync with prop if it updates
  React.useEffect(() => {
    if (initialThreshold) {
      setThresholdData(initialThreshold);
    }
  }, [initialThreshold]);

  const handleManualRecalibrate = () => {
    setIsRecalibrating(true);
    setTimeout(() => {
      // Re-run real genuine simulation measurements (25 batches of 1024 shots)
      const newSamples = generateGenuineSimulationMeasurements(25, 1024);
      const curr = thresholdData?.currentMeasurement ?? 50.8;
      const updated = calculateAdaptiveThreshold(newSamples, curr);
      setThresholdData(updated);
      if (onRecalibrate) onRecalibrate(updated);
      setIsRecalibrating(false);
    }, 400);
  };

  if (!thresholdData) {
    return (
      <div id="adaptive-threshold-section-empty" className={`bg-[#111827] border border-[#1E293B] rounded p-4 text-xs ${className}`}>
        <div className="flex items-center gap-2 text-[#94A3B8]">
          <Activity className="w-4 h-4 text-[#38BDF8]" />
          <span className="font-semibold uppercase tracking-wider text-[11px] text-[#F1F5F9]">
            Adaptive Statistical Threshold
          </span>
        </div>
        <p className="mt-2 text-[11px] text-[#94A3B8]">
          Insufficient genuine samples for statistical calibration. Execute an artifact analysis to populate genuine simulation baselines.
        </p>
      </div>
    );
  }

  const {
    sampleCount,
    mean,
    standardDeviation,
    minimum,
    maximum,
    lowerThreshold,
    upperThreshold,
    currentMeasurement,
    isWithinRange,
    statisticalAnomaly,
    status,
    insufficientData,
    expectedRangeDisplay
  } = thresholdData;

  // Visual range scaling calculation
  // Expand domain bounds slightly so currentMeasurement, min, max, lower, upper all fit with margins
  const domainMin = Math.max(0, Math.min(minimum, lowerThreshold, currentMeasurement) - 4);
  const domainMax = Math.min(100, Math.max(maximum, upperThreshold, currentMeasurement) + 4);
  const domainSpan = Math.max(1, domainMax - domainMin);

  const getPercentPos = (val: number) => {
    const clampedVal = Math.max(domainMin, Math.min(domainMax, val));
    return ((clampedVal - domainMin) / domainSpan) * 100;
  };

  const lowerPct = getPercentPos(lowerThreshold);
  const upperPct = getPercentPos(upperThreshold);
  const currentPct = getPercentPos(currentMeasurement);
  const minPct = getPercentPos(minimum);
  const maxPct = getPercentPos(maximum);

  return (
    <div
      id="adaptive-statistical-threshold-card"
      className={`bg-[#111827] border border-[#1E293B] rounded overflow-hidden shadow-xs ${className}`}
    >
      {/* Header bar */}
      <div className="px-4 py-3 bg-[#162032] border-b border-[#1E293B] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-[#0284C7]/20 text-[#38BDF8] rounded border border-[#0284C7]/40">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
                Adaptive Statistical Threshold
              </h3>
              <span className="text-[10px] font-mono text-[#94A3B8] bg-[#111827] border border-[#1E293B] px-1.5 py-0.5 rounded">
                Statistical Calibration
              </span>
            </div>
            <p className="text-[11px] text-[#94A3B8]">
              Mean ± 2σ bounds derived from real simulation measurement datasets
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Status Badge */}
          {insufficientData ? (
            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#94A3B8] bg-[#162032] border border-[#1E293B] px-2.5 py-1 rounded font-mono">
              <Info className="w-3.5 h-3.5 text-[#94A3B8]" />
              <span>Insufficient Genuine Samples</span>
            </span>
          ) : isWithinRange ? (
            <span className="inline-flex items-center gap-1 text-[11px] font-bold font-mono text-[#34D399] bg-[#064E3B]/40 border border-[#065F46] px-2.5 py-1 rounded">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#34D399]" />
              <span>Within Normal Range</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-[11px] font-bold font-mono text-[#F87171] bg-[#7F1D1D]/40 border border-[#991B1B] px-2.5 py-1 rounded">
              <AlertTriangle className="w-3.5 h-3.5 text-[#F87171]" />
              <span>Statistical Anomaly Detected</span>
            </span>
          )}

          <button
            id="recalibrate-threshold-btn"
            onClick={handleManualRecalibrate}
            disabled={isRecalibrating}
            title="Recalibrate thresholds using real simulation engine execution"
            className="p-1.5 text-[#94A3B8] hover:text-[#38BDF8] hover:bg-[#1E293B] rounded border border-[#1E293B] cursor-pointer transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRecalibrating ? 'animate-spin text-[#38BDF8]' : ''}`} />
          </button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Metric Grid (University-grade research layout) */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
          <div className="p-2.5 bg-[#162032] border border-[#1E293B] rounded text-center">
            <span className="block text-[10px] uppercase font-semibold text-[#94A3B8]">Genuine Samples</span>
            <span className="text-sm font-bold font-mono text-[#F1F5F9]">{sampleCount}</span>
            <span className="block text-[9px] text-[#64748B]">Sim batches</span>
          </div>

          <div className="p-2.5 bg-[#162032] border border-[#1E293B] rounded text-center">
            <span className="block text-[10px] uppercase font-semibold text-[#94A3B8]">Mean (μ)</span>
            <span className="text-sm font-bold font-mono text-[#38BDF8]">{mean.toFixed(2)}%</span>
            <span className="block text-[9px] text-[#64748B]">Baseline center</span>
          </div>

          <div className="p-2.5 bg-[#162032] border border-[#1E293B] rounded text-center">
            <span className="block text-[10px] uppercase font-semibold text-[#94A3B8]">Std Dev (σ)</span>
            <span className="text-sm font-bold font-mono text-[#F1F5F9]">{standardDeviation.toFixed(2)}%</span>
            <span className="block text-[9px] text-[#64748B]">Population σ</span>
          </div>

          <div className="p-2.5 bg-[#162032] border border-[#1E293B] rounded text-center">
            <span className="block text-[10px] uppercase font-semibold text-[#94A3B8]">Minimum</span>
            <span className="text-sm font-bold font-mono text-[#64748B]">{minimum.toFixed(2)}%</span>
            <span className="block text-[9px] text-[#64748B]">Sample floor</span>
          </div>

          <div className="p-2.5 bg-[#162032] border border-[#1E293B] rounded text-center">
            <span className="block text-[10px] uppercase font-semibold text-[#94A3B8]">Maximum</span>
            <span className="text-sm font-bold font-mono text-[#64748B]">{maximum.toFixed(2)}%</span>
            <span className="block text-[9px] text-[#64748B]">Sample ceiling</span>
          </div>

          <div className="p-2.5 bg-[#162032] border border-[#1E293B] rounded text-center">
            <span className="block text-[10px] uppercase font-semibold text-[#94A3B8]">Lower (μ - 2σ)</span>
            <span className="text-sm font-bold font-mono text-[#38BDF8]">{lowerThreshold.toFixed(2)}%</span>
            <span className="block text-[9px] text-[#64748B]">Min allowable</span>
          </div>

          <div className="p-2.5 bg-[#162032] border border-[#1E293B] rounded text-center">
            <span className="block text-[10px] uppercase font-semibold text-[#94A3B8]">Upper (μ + 2σ)</span>
            <span className="text-sm font-bold font-mono text-[#38BDF8]">{upperThreshold.toFixed(2)}%</span>
            <span className="block text-[9px] text-[#64748B]">Max allowable</span>
          </div>

          <div className={`p-2.5 border rounded text-center ${
            statisticalAnomaly
              ? 'bg-[#7F1D1D]/30 border-[#991B1B]'
              : 'bg-[#064E3B]/30 border-[#065F46]'
          }`}>
            <span className="block text-[10px] uppercase font-semibold text-[#94A3B8]">Current Value</span>
            <span className={`text-sm font-bold font-mono ${
              statisticalAnomaly ? 'text-[#F87171]' : 'text-[#34D399]'
            }`}>
              {currentMeasurement.toFixed(2)}%
            </span>
            <span className="block text-[9px] text-[#64748B]">Artifact value</span>
          </div>
        </div>

        {/* Range Visualization Bar */}
        <div className="bg-[#162032] border border-[#1E293B] rounded p-3.5 space-y-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between text-[11px] gap-1">
            <span className="font-semibold text-[#F1F5F9] flex items-center gap-1.5">
              <BarChart2 className="w-3.5 h-3.5 text-[#38BDF8]" />
              Statistical Measurement Range Visualization
            </span>
            <span className="font-mono text-[#94A3B8]">
              Expected Normal Range: <strong className="text-[#F1F5F9] font-semibold">{expectedRangeDisplay}</strong>
            </span>
          </div>

          {/* Diagram Container */}
          <div className="pt-5 pb-6 px-3 relative">
            {/* Background Track */}
            <div className="w-full h-3 bg-[#1E293B] rounded-full relative overflow-visible border border-[#334155]">
              {/* Calibrated Normal Range (Mean ± 2σ) Zone */}
              <div
                className="absolute top-0 bottom-0 bg-[#065F46]/60 border-x border-[#10B981]"
                style={{
                  left: `${Math.max(0, lowerPct)}%`,
                  width: `${Math.max(1, upperPct - lowerPct)}%`
                }}
                title={`Normal Calibrated Range: ${lowerThreshold.toFixed(2)}% — ${upperThreshold.toFixed(2)}%`}
              />

              {/* Lower Threshold Marker Tick */}
              <div
                className="absolute top-[-5px] bottom-[-5px] w-0.5 bg-[#34D399] z-10"
                style={{ left: `${lowerPct}%` }}
              />

              {/* Upper Threshold Marker Tick */}
              <div
                className="absolute top-[-5px] bottom-[-5px] w-0.5 bg-[#34D399] z-10"
                style={{ left: `${upperPct}%` }}
              />

              {/* Mean Marker Tick */}
              <div
                className="absolute top-[-3px] bottom-[-3px] w-0.5 bg-[#38BDF8] z-10 opacity-70"
                style={{ left: `${getPercentPos(mean)}%` }}
                title={`Mean: ${mean.toFixed(2)}%`}
              />

              {/* Current Measurement Pin Indicator */}
              <div
                className="absolute top-1/2 -translate-y-1/2 -translate-x-1/2 z-20"
                style={{ left: `${Math.max(2, Math.min(98, currentPct))}%` }}
              >
                <div
                  className={`w-4 h-4 rounded-full border-2 shadow-sm flex items-center justify-center ${
                    statisticalAnomaly
                      ? 'bg-[#EF4444] border-[#111827] ring-2 ring-[#F87171]'
                      : 'bg-[#10B981] border-[#111827] ring-2 ring-[#34D399]'
                  }`}
                  title={`Current Measurement: ${currentMeasurement.toFixed(2)}% (${status})`}
                />
              </div>
            </div>

            {/* Position Labels Below Bar */}
            <div className="relative mt-2 text-[10px] font-mono text-[#94A3B8] h-5">
              <span
                className="absolute -translate-x-1/2 text-left"
                style={{ left: `${Math.max(6, Math.min(94, lowerPct))}%` }}
              >
                Lower: {lowerThreshold.toFixed(1)}%
              </span>
              <span
                className="absolute -translate-x-1/2 font-semibold text-[#38BDF8]"
                style={{ left: `${Math.max(6, Math.min(94, getPercentPos(mean)))}%` }}
              >
                μ: {mean.toFixed(1)}%
              </span>
              <span
                className="absolute -translate-x-1/2 text-right"
                style={{ left: `${Math.max(6, Math.min(94, upperPct))}%` }}
              >
                Upper: {upperThreshold.toFixed(1)}%
              </span>
            </div>

            {/* Current Measurement Pin Callout */}
            <div className="flex items-center justify-center gap-2 pt-1 text-[11px] font-mono">
              <span className="text-[#94A3B8]">Current Measurement Observed:</span>
              <span
                className={`font-bold px-2 py-0.5 rounded border ${
                  statisticalAnomaly
                    ? 'text-[#F87171] bg-[#7F1D1D]/40 border-[#991B1B]'
                    : 'text-[#34D399] bg-[#064E3B]/40 border-[#065F46]'
                }`}
              >
                {currentMeasurement.toFixed(2)}% ({status})
              </span>
            </div>
          </div>
        </div>

        {/* WHY THIS VERDICT? Accordion/Card */}
        <div className="border border-[#1E293B] rounded overflow-hidden">
          <button
            id="toggle-why-this-verdict-btn"
            onClick={() => setShowExplanation(!showExplanation)}
            className="w-full px-3.5 py-2.5 bg-[#162032] hover:bg-[#1E293B] text-left flex items-center justify-between text-xs font-bold text-[#F1F5F9] cursor-pointer transition"
          >
            <span className="flex items-center gap-2 font-mono">
              <HelpCircle className="w-3.5 h-3.5 text-[#38BDF8]" />
              WHY THIS VERDICT? (STATISTICAL CALIBRATION EXPLANATION)
            </span>
            {showExplanation ? <ChevronUp className="w-4 h-4 text-[#94A3B8]" /> : <ChevronDown className="w-4 h-4 text-[#94A3B8]" />}
          </button>

          {showExplanation && (
            <div className="p-3.5 space-y-2.5 text-xs text-[#F1F5F9] bg-[#111827] border-t border-[#1E293B]">
              <ol className="space-y-1.5 font-mono text-[11px] text-[#94A3B8] list-decimal list-inside">
                <li>
                  <strong className="text-[#F1F5F9]">Genuine signer measurements were collected:</strong> Analyzed {sampleCount} genuine simulation batches from the existing QDS engine.
                </li>
                <li>
                  <strong className="text-[#F1F5F9]">Statistical calibration calculated the mean:</strong> Baseline average measurement established at <span className="text-[#38BDF8] font-bold">{mean.toFixed(2)}%</span>.
                </li>
                <li>
                  <strong className="text-[#F1F5F9]">Standard deviation measured normal variation:</strong> Population standard deviation calculated at <span className="font-semibold text-[#F1F5F9]">{standardDeviation.toFixed(2)}%</span>.
                </li>
                <li>
                  <strong className="text-[#F1F5F9]">Acceptable range generated using Mean ± 2σ:</strong> Normal operational threshold bounds defined as <span className="font-semibold text-[#38BDF8]">{expectedRangeDisplay}</span>.
                </li>
                <li>
                  <strong className="text-[#F1F5F9]">Current measurement evaluated:</strong> Artifact measurement observed at <span className={`font-bold ${statisticalAnomaly ? 'text-[#F87171]' : 'text-[#34D399]'}`}>{currentMeasurement.toFixed(2)}%</span>.
                </li>
                <li>
                  <strong className="text-[#F1F5F9]">Classification:</strong> {statisticalAnomaly ? (
                    <span className="text-[#F87171] font-bold">Outside-range result flagged as a statistical anomaly (Statistical Anomaly Detected).</span>
                  ) : (
                    <span className="text-[#34D399] font-semibold">Measurement confirmed within calibrated bounds (Within Normal Range).</span>
                  )}
                </li>
                <li>
                  <strong className="text-[#F1F5F9]">Final Decision:</strong> The statistical anomaly result is passed as an additional indicator into the existing Q Shield threat correlation logic to determine the final security verdict.
                </li>
              </ol>

              <div className="pt-2 border-t border-[#1E293B] flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[10px] text-[#64748B]">
                <span>
                  <strong>Technical Note:</strong> Thresholds are derived statistically from genuine simulation measurements. An anomaly indicates deviation from the calibrated distribution and is not, by itself, proof of an attack.
                </span>
                <span className="shrink-0 italic text-[9px] text-[#64748B]">
                  Population σ (N in denominator) | Domain clamped to [0%, 100%]
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Quantum Simulation Telemetry Disclaimer */}
        <div className="text-[10px] text-[#64748B] italic border-t border-[#1E293B] pt-2">
          Disclaimer: Quantum operations in Q Shield are software-based simulations and do not represent measurements from physical quantum hardware.
        </div>
      </div>
    </div>
  );
};
export default AdaptiveThresholdSection;
