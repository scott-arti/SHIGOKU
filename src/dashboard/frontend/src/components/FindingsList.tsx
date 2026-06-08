import { Finding } from '../services/api';

interface FindingsListProps {
  findings: Finding[];
}

function FindingsList({ findings }: FindingsListProps) {
  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: 'bg-red-900/30 text-red-400 border-red-500',
      high: 'bg-orange-900/30 text-orange-400 border-orange-500',
      medium: 'bg-yellow-900/30 text-yellow-400 border-yellow-500',
      low: 'bg-green-900/30 text-green-400 border-green-500',
      info: 'bg-blue-900/30 text-blue-400 border-blue-500',
    };
    return colors[severity as keyof typeof colors] || colors.info;
  };

  const getSeverityIcon = (severity: string) => {
    const icons = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: '🔵',
    };
    return icons[severity as keyof typeof icons] || '⚪';
  };

  if (findings.length === 0) {
    return (
      <div className="text-center py-12 text-gray-400">
        該当する脆弱性が見つかりませんでした
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {findings.map((finding) => (
        <div
          key={finding.id}
          className="bg-slate-700/50 rounded-lg p-6 border-l-4 hover:bg-slate-700 transition-colors"
          style={{
            borderLeftColor: getSeverityColor(finding.severity).includes('red')
              ? '#ef4444'
              : getSeverityColor(finding.severity).includes('orange')
              ? '#f97316'
              : getSeverityColor(finding.severity).includes('yellow')
              ? '#eab308'
              : getSeverityColor(finding.severity).includes('green')
              ? '#22c55e'
              : '#3b82f6',
          }}
        >
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <span className="text-2xl">{getSeverityIcon(finding.severity)}</span>
                <h3 className="text-lg font-semibold text-white">
                  {finding.title}
                </h3>
              </div>

              <p className="text-gray-300 text-sm mb-3">{finding.description}</p>

              <div className="flex flex-wrap gap-2 mb-3">
                <span
                  className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(
                    finding.severity
                  )}`}
                >
                  {finding.severity.toUpperCase()}
                </span>

                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-600 text-gray-300">
                  {finding.vuln_type}
                </span>

                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-900/30 text-indigo-400">
                  確信度: {(finding.confidence * 100).toFixed(0)}%
                </span>

                {finding.cwe_id && (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-900/30 text-purple-400">
                    {finding.cwe_id}
                  </span>
                )}

                {finding.cvss_score && (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-pink-900/30 text-pink-400">
                    CVSS: {finding.cvss_score.toFixed(1)}
                  </span>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm text-gray-400">
                <div>
                  <span className="font-medium">ターゲット:</span>{' '}
                  <span className="text-gray-300">{finding.target_url}</span>
                </div>
                <div>
                  <span className="font-medium">エージェント:</span>{' '}
                  <span className="text-gray-300">{finding.source_agent}</span>
                </div>
                <div>
                  <span className="font-medium">発見日時:</span>{' '}
                  <span className="text-gray-300">
                    {new Date(finding.discovered_at).toLocaleString('ja-JP')}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default FindingsList;
