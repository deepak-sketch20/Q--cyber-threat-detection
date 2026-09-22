import React, { useEffect, useRef } from 'react';
import {
  Chart,
  BarController,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip
} from 'chart.js';

Chart.register(BarController, BarElement, CategoryScale, LinearScale, Tooltip);

interface ThreatDistributionChartProps {
  items: Array<{
    label: string;
    value: number;
    detected: boolean;
  }>;
  theme?: 'light' | 'dark';
}

export const ThreatDistributionChart: React.FC<ThreatDistributionChartProps> = ({ items, theme }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const chartInstanceRef = useRef<Chart | null>(null);

  useEffect(() => {
    if (!canvasRef.current) return;

    // Destroy existing chart if present
    if (chartInstanceRef.current) {
      chartInstanceRef.current.destroy();
      chartInstanceRef.current = null;
    }

    const ctx = canvasRef.current.getContext('2d');
    if (!ctx) return;

    const isLight = theme === 'light' || document.documentElement.classList.contains('light');

    const labels = items.map(item => item.label);
    const dataValues = items.map(item => item.value);
    const backgroundColors = items.map(item => {
      if (item.detected) {
        return item.label.includes('Quantum') || item.label.includes('Eavesdrop')
          ? '#0284C7'
          : '#EF4444';
      }
      return isLight ? '#E2E8F0' : '#1E293B';
    });

    const borderColors = items.map(item => {
      if (item.detected) {
        return item.label.includes('Quantum') || item.label.includes('Eavesdrop')
          ? '#0284C7'
          : '#DC2626';
      }
      return isLight ? '#CBD5E1' : '#334155';
    });

    chartInstanceRef.current = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            data: dataValues,
            backgroundColor: backgroundColors,
            borderColor: borderColors,
            borderWidth: 1,
            borderRadius: 3,
            barThickness: 14
          }
        ]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            callbacks: {
              label: (context) => {
                const val = context.raw as number;
                return ` Threat Indicator Weight: ${val}%`;
              }
            },
            backgroundColor: isLight ? '#FFFFFF' : '#0E1526',
            borderColor: isLight ? '#CBD5E1' : '#1E293B',
            borderWidth: 1,
            titleColor: '#0284C7',
            bodyColor: isLight ? '#0F172A' : '#F1F5F9',
            titleFont: { family: 'ui-monospace, monospace', size: 11, weight: 'bold' },
            bodyFont: { family: 'ui-sans-serif, system-ui, sans-serif', size: 11 },
            padding: 8,
            cornerRadius: 4
          }
        },
        scales: {
          x: {
            min: 0,
            max: 100,
            grid: {
              color: isLight ? '#E2E8F0' : '#1E293B'
            },
            ticks: {
              color: isLight ? '#475569' : '#94A3B8',
              font: { family: 'ui-monospace, monospace', size: 10 },
              callback: (val) => `${val}%`
            },
            border: {
              color: isLight ? '#CBD5E1' : '#334155'
            }
          },
          y: {
            grid: {
              display: false
            },
            ticks: {
              color: isLight ? '#0F172A' : '#F1F5F9',
              font: { family: 'ui-sans-serif, system-ui, sans-serif', size: 11, weight: 'bold' }
            },
            border: {
              color: isLight ? '#CBD5E1' : '#334155'
            }
          }
        }
      }
    });

    return () => {
      if (chartInstanceRef.current) {
        chartInstanceRef.current.destroy();
        chartInstanceRef.current = null;
      }
    };
  }, [items, theme]);

  return (
    <div className="w-full h-44">
      <canvas ref={canvasRef} />
    </div>
  );
};
