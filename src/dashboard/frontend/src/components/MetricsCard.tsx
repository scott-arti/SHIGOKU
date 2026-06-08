import React from 'react';
import { SessionMetrics } from '../services/api';

interface MetricsCardProps {
  metrics: SessionMetrics;
}

const MetricsCard: React.FC<MetricsCardProps> = ({ metrics }) => {
  const { performance } = metrics;
  const skipReasonEntries = Object.entries(metrics.skip_reason_counts || {}).sort((a, b) => b[1] - a[1]);
  const skipReasonUnknownEntries = Object.entries(metrics.skip_reason_unknown_counts || {}).sort((a, b) => b[1] - a[1]);
  const totalSkipReasons = skipReasonEntries.reduce((acc, [, count]) => acc + count, 0);
  const lowSsrfBreakdownEntries = Object.entries(metrics.low_ssrf_score_breakdown || {}).sort((a, b) => b[1] - a[1]);
  const lowSsrfBreakdownTotal = lowSsrfBreakdownEntries.reduce((acc, [, count]) => acc + count, 0);
  const timeline = metrics.skip_reason_timeline || [];
  const unknownAlert = metrics.skip_reason_unknown_alert;
  
  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    const mins = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return `${mins}m ${secs}s`;
  };

  const taskSuccessRatio = performance.total_tasks > 0
    ? (performance.successful_tasks / performance.total_tasks) * 100
    : 0;
  const taskFailRatio = performance.total_tasks > 0
    ? (performance.failed_tasks / performance.total_tasks) * 100
    : 0;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
      <h2 className="text-xl font-bold text-white mb-6 flex items-center">
        <span className="mr-2">📊</span> 実行メトリクス
      </h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm mb-1 font-medium">実行時間</div>
          <div className="text-2xl font-bold text-cyan-400">{formatDuration(performance.total_duration)}</div>
        </div>
        
        <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm mb-1 font-medium">推定コスト</div>
          <div className="text-2xl font-bold text-emerald-400">${performance.estimated_cost.toFixed(4)}</div>
        </div>
        
        <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm mb-1 font-medium">成功率</div>
          <div className="text-2xl font-bold text-indigo-400">{(performance.success_rate * 100).toFixed(1)}%</div>
          <div className="w-full bg-slate-700 h-1.5 rounded-full mt-2 overflow-hidden">
            <div 
              className="bg-indigo-500 h-full rounded-full" 
              style={{ width: `${performance.success_rate * 100}%` }}
            />
          </div>
        </div>
        
        <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm mb-1 font-medium">処理速度</div>
          <div className="text-2xl font-bold text-amber-400">{performance.tasks_per_minute.toFixed(1)} <span className="text-sm font-normal text-slate-500">tpm</span></div>
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-slate-300">総タスク数</span>
          <span className="text-white font-bold">{performance.total_tasks}</span>
        </div>
        
        <div className="w-full bg-slate-800 h-4 rounded-full flex overflow-hidden">
          <div 
            className="bg-emerald-500 h-full transition-all" 
            style={{ width: `${taskSuccessRatio}%` }}
            title={`Success: ${performance.successful_tasks}`}
          />
          <div 
            className="bg-red-500 h-full transition-all" 
            style={{ width: `${taskFailRatio}%` }}
            title={`Failed: ${performance.failed_tasks}`}
          />
        </div>
        
        <div className="flex gap-4 text-xs">
          <div className="flex items-center">
            <div className="w-2 h-2 bg-emerald-500 rounded-full mr-2"></div>
            <span className="text-slate-400">成功: {performance.successful_tasks}</span>
          </div>
          <div className="flex items-center">
            <div className="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
            <span className="text-slate-400">失敗: {performance.failed_tasks}</span>
          </div>
        </div>
      </div>
      
      {Object.keys(metrics.phase_breakdown).length > 0 && (
        <div className="mt-8">
          <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">フェーズ別内訳</h3>
          <div className="space-y-3">
            {Object.entries(metrics.phase_breakdown).map(([phase, duration]) => (
              <div key={phase} className="space-y-1">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 capitalize">{phase}</span>
                  <span className="text-slate-400">{formatDuration(duration)}</span>
                </div>
                <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                  <div 
                    className="bg-blue-500 h-full" 
                    style={{ width: `${(duration / performance.total_duration) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {skipReasonEntries.length > 0 && (
        <div className="mt-8">
          <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Skip Reason内訳</h3>
          <div className="text-xs text-slate-500 mb-2">
            other ratio: {(Number(metrics.skip_reason_other_ratio || 0) * 100).toFixed(1)}%
          </div>
          <div className="space-y-2">
            {skipReasonEntries.map(([reason, count]) => {
              const ratio = totalSkipReasons > 0 ? (count / totalSkipReasons) * 100 : 0;
              return (
                <div key={reason} className="bg-slate-800/50 border border-slate-700 rounded-md p-3">
                  <div className="flex items-center justify-between text-xs mb-2">
                    <span className="text-slate-300 font-mono">{reason}</span>
                    <span className="text-slate-400">{count} ({ratio.toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-orange-500 h-full" style={{ width: `${ratio}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {skipReasonUnknownEntries.length > 0 && (
        <div className="mt-8">
          <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Skip Reason Unknown内訳 (Top)</h3>
          {unknownAlert?.triggered && (
            <div className="mb-3 rounded-md border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-300">
              unknown急増アラート: {unknownAlert.unknown_count}/{unknownAlert.total_skip_count} ({(unknownAlert.unknown_ratio * 100).toFixed(1)}%)
            </div>
          )}
          <div className="space-y-2">
            {skipReasonUnknownEntries.slice(0, 5).map(([reason, count]) => (
              <div key={reason} className="bg-slate-800/50 border border-slate-700 rounded-md p-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-mono">{reason}</span>
                  <span className="text-slate-400">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {lowSsrfBreakdownEntries.length > 0 && (
        <div className="mt-8">
          <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">low_ssrf_score 内訳（不足特徴 TOP）</h3>
          {metrics.low_ssrf_top_missing_feature && (
            <div className="text-xs text-slate-500 mb-2">
              top missing feature: <span className="font-mono text-slate-300">{metrics.low_ssrf_top_missing_feature}</span>
            </div>
          )}
          <div className="space-y-2">
            {lowSsrfBreakdownEntries.slice(0, 5).map(([feature, count]) => {
              const ratio = lowSsrfBreakdownTotal > 0 ? (count / lowSsrfBreakdownTotal) * 100 : 0;
              return (
                <div key={feature} className="bg-slate-800/50 border border-slate-700 rounded-md p-3">
                  <div className="flex items-center justify-between text-xs mb-2">
                    <span className="text-slate-300 font-mono">{feature}</span>
                    <span className="text-slate-400">{count} ({ratio.toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-rose-500 h-full" style={{ width: `${ratio}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {timeline.length > 0 && (
        <div className="mt-8">
          <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Skip Reason時系列（累積）</h3>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {timeline.map((point) => {
              const cumulativeTotal = Object.values(point.cumulative || {}).reduce((acc, value) => acc + value, 0);
              const deltaSummary = Object.entries(point.delta || {})
                .filter(([, value]) => value > 0)
                .map(([key, value]) => `${key}: +${value}`)
                .join(', ');
              return (
                <div key={`${point.task_index}-${point.task_id}`} className="bg-slate-800/50 border border-slate-700 rounded-md p-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300">#{point.task_index} {point.task_name || point.task_id}</span>
                    <span className="text-cyan-300 font-semibold">累積 {cumulativeTotal}</span>
                  </div>
                  {deltaSummary && (
                    <div className="text-[11px] text-slate-400 mt-1">{deltaSummary}</div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default MetricsCard;
