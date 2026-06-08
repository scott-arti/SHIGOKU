import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { projectsApi, Finding, VulnerabilityScore, SessionMetrics } from '../services/api';
import FindingsList from '../components/FindingsList';
import VulnerabilityScoreCard from '../components/VulnerabilityScoreCard';
import MetricsCard from '../components/MetricsCard';

function ProjectDetail() {
  const { projectName } = useParams<{ projectName: string }>();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [score, setScore] = useState<VulnerabilityScore | null>(null);
  const [metrics, setMetrics] = useState<SessionMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // フィルタ状態
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [vulnTypeFilter, setVulnTypeFilter] = useState<string>('');
  const [minConfidence, setMinConfidence] = useState<number>(0);

  useEffect(() => {
    if (projectName) {
      loadProjectData();
    }
  }, [projectName, severityFilter, vulnTypeFilter, minConfidence]);

  const loadProjectData = async () => {
    if (!projectName) return;

    try {
      setLoading(true);
      setError(null);

      const [findingsRes, scoreRes, metricsRes] = await Promise.all([
        projectsApi.getFindings(projectName, {
          severity: severityFilter || undefined,
          vuln_type: vulnTypeFilter || undefined,
          min_confidence: minConfidence || undefined,
        }),
        projectsApi.getScore(projectName),
        projectsApi.getMetrics(projectName).catch(() => ({ data: null })), // Optional
      ]);

      setFindings(findingsRes.data);
      setScore(scoreRes.data);
      if (metricsRes.data) setMetrics(metricsRes.data);
    } catch (err) {
      setError('データの取得に失敗しました');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-400">読み込み中...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-500 rounded-lg p-4">
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-white">{projectName}</h1>
        <p className="text-gray-400 mt-2">プロジェクト詳細</p>
      </div>

      {/* スコアとメトリクス */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        <div className="lg:col-span-1">
          {score && <VulnerabilityScoreCard score={score} />}
        </div>
        <div className="lg:col-span-2">
          {metrics && <MetricsCard metrics={metrics} />}
        </div>
      </div>

      {/* Findings一覧 */}
      <div className="bg-slate-800 rounded-lg p-6">
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-white mb-4">発見された脆弱性</h2>

          {/* フィルタバー */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                深刻度
              </label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                <option value="">すべて</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                最小確信度
              </label>
              <input
                type="range"
                min="0"
                max="100"
                value={minConfidence * 100}
                onChange={(e) => setMinConfidence(Number(e.target.value) / 100)}
                className="w-full"
              />
              <div className="text-sm text-gray-400 mt-1">
                {(minConfidence * 100).toFixed(0)}%
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                脆弱性タイプ
              </label>
              <input
                type="text"
                value={vulnTypeFilter}
                onChange={(e) => setVulnTypeFilter(e.target.value)}
                placeholder="例: jwt_alg_none"
                className="w-full bg-slate-700 border border-slate-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
          </div>
        </div>

        <FindingsList findings={findings} />
      </div>
    </div>
  );
}

export default ProjectDetail;
