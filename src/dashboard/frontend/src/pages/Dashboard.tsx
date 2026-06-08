import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { projectsApi, ProjectInfo } from '../services/api';

function Dashboard() {
  const [projects, setProjects] = useState<ProjectInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadProjects();
  }, []);

  const loadProjects = async () => {
    try {
      setLoading(true);
      const response = await projectsApi.list();
      setProjects(response.data);
    } catch (err) {
      setError('プロジェクト一覧の取得に失敗しました');
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
        <h1 className="text-3xl font-bold text-white">プロジェクト一覧</h1>
        <p className="text-gray-400 mt-2">
          {projects.length}個のプロジェクト
        </p>
      </div>

      {projects.length === 0 ? (
        <div className="bg-slate-800 rounded-lg p-8 text-center">
          <p className="text-gray-400">プロジェクトがありません</p>
          <p className="text-sm text-gray-500 mt-2">
            CLIからハンティングを実行してプロジェクトを作成してください
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <Link
              key={project.project_name}
              to={`/project/${project.project_name}`}
              className="bg-slate-800 rounded-lg p-6 hover:bg-slate-700 transition-colors border border-slate-700 hover:border-indigo-500"
            >
              <div className="flex items-start justify-between">
                <h2 className="text-xl font-semibold text-white">
                  {project.project_name}
                </h2>
                {project.total_findings > 0 && (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-900/30 text-red-400">
                    {project.total_findings}件
                  </span>
                )}
              </div>

              <p className="text-gray-400 text-sm mt-2 line-clamp-2">
                {project.target_url}
              </p>

              {project.program_name && (
                <p className="text-indigo-400 text-sm mt-2">
                  {project.program_name}
                </p>
              )}

              <div className="mt-4 flex flex-wrap gap-2">
                {project.tags.map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-slate-700 text-gray-300"
                  >
                    {tag}
                  </span>
                ))}
              </div>

              <div className="mt-4 text-xs text-gray-500">
                作成: {new Date(project.created_at).toLocaleDateString('ja-JP')}
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

export default Dashboard;
