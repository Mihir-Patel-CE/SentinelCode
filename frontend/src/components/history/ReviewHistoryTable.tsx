import React, { useState, useEffect, useCallback } from 'react';
import { Search, Download, Trash2, ExternalLink, RefreshCw } from 'lucide-react';
import type { ReviewListResponse } from '../../types';
import { api } from '../../services/api';

interface ReviewHistoryTableProps {
  onSelectReview: (id: number) => void;
}

export const ReviewHistoryTable: React.FC<ReviewHistoryTableProps> = ({ onSelectReview }) => {
  const [data, setData] = useState<ReviewListResponse>({ items: [], total: 0, page: 1, size: 10, pages: 1 });
  const [loading, setLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  const [language, setLanguage] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null);

  const fetchReviews = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.listReviews({
        page,
        size: 10,
        language: language || undefined,
        q: search || undefined,
      });
      setData(res);
    } catch (err) {
      console.error('Failed to load reviews:', err);
    } finally {
      setLoading(false);
    }
  }, [page, language, search]);

  useEffect(() => {
    let ignore = false;
    api.listReviews({
      page,
      size: 10,
      language: language || undefined,
      q: search || undefined,
    }).then((res) => {
      if (!ignore) {
        setData(res);
        setLoading(false);
      }
    }).catch((err) => {
      if (!ignore) {
        console.error('Failed to load reviews:', err);
        setLoading(false);
      }
    });

    return () => {
      ignore = true;
    };
  }, [page, language, search]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchReviews();
  };

  const handleDelete = async (id: number) => {
    try {
      await api.deleteReview(id);
      setDeleteConfirmId(null);
      fetchReviews();
    } catch (err) {
      console.error('Delete failed:', err);
    }
  };

  const getScoreBadge = (score: number | null) => {
    if (score === null) return 'text-slate-400 bg-slate-900 border-slate-800';
    if (score >= 90) return 'text-emerald-400 bg-emerald-950/40 border-emerald-800/40';
    if (score >= 70) return 'text-blue-400 bg-blue-950/40 border-blue-800/40';
    if (score >= 50) return 'text-amber-400 bg-amber-950/40 border-amber-800/40';
    return 'text-rose-400 bg-rose-950/40 border-rose-800/40';
  };

  return (
    <div className="space-y-4">
      {/* Search and Filters Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-slate-900 border border-slate-800 rounded-xl">
        <form onSubmit={handleSearchSubmit} className="flex items-center space-x-2 flex-1 min-w-[240px]">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search audit title..."
              className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
          >
            Search
          </button>
        </form>

        <div className="flex items-center space-x-3">
          <select
            value={language}
            onChange={(e) => {
              setLanguage(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Languages</option>
            <option value="python">Python</option>
            <option value="javascript">JavaScript</option>
            <option value="typescript">TypeScript</option>
            <option value="java">Java</option>
          </select>

          <button
            onClick={fetchReviews}
            title="Refresh list"
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 rounded-lg transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Reviews Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Audit Title</th>
                <th className="px-4 py-3">Language</th>
                <th className="px-4 py-3">Security Score</th>
                <th className="px-4 py-3">Quality Score</th>
                <th className="px-4 py-3">Issues Found</th>
                <th className="px-4 py-3">Date</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {loading && data.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                    <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-blue-400" />
                    <span>Loading audit records...</span>
                  </td>
                </tr>
              ) : data.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                    No audits match your criteria. Run an audit in the workspace first!
                  </td>
                </tr>
              ) : (
                data.items.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-medium text-slate-200">
                      <button
                        onClick={() => onSelectReview(item.id)}
                        className="hover:text-blue-400 text-left transition-colors"
                      >
                        {item.title}
                      </button>
                    </td>
                    <td className="px-4 py-3 font-mono uppercase text-slate-400 text-[11px]">
                      {item.language}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getScoreBadge(item.security_score)}`}>
                        {item.security_score !== null ? `${item.security_score}/100` : 'N/A'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getScoreBadge(item.quality_score)}`}>
                        {item.quality_score !== null ? `${item.quality_score}/100` : 'N/A'}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-slate-300">
                      {item.total_findings} {item.total_findings === 1 ? 'finding' : 'findings'}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-[11px]">
                      {new Date(item.created_at).toLocaleDateString()} {new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        {/* View in Workspace */}
                        <button
                          onClick={() => onSelectReview(item.id)}
                          title="Open audit details"
                          className="p-1.5 text-slate-400 hover:text-blue-400 hover:bg-slate-800 rounded transition-colors"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </button>

                        {/* Export Markdown */}
                        <a
                          href={api.getExportUrl(item.id)}
                          download
                          title="Download Markdown audit report"
                          className="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition-colors"
                        >
                          <Download className="h-4 w-4" />
                        </a>

                        {/* Delete */}
                        {deleteConfirmId === item.id ? (
                          <div className="flex items-center space-x-1">
                            <button
                              onClick={() => handleDelete(item.id)}
                              className="px-2 py-0.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-[10px] font-bold"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setDeleteConfirmId(null)}
                              className="px-1.5 py-0.5 bg-slate-800 text-slate-400 rounded text-[10px]"
                            >
                              ✕
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setDeleteConfirmId(item.id)}
                            title="Delete audit"
                            className="p-1.5 text-slate-500 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        {data.pages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 bg-slate-950 border-t border-slate-800 text-xs text-slate-400">
            <span>
              Showing {data.items.length} of {data.total} audits (Page {data.page} of {data.pages})
            </span>
            <div className="flex items-center space-x-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800 text-slate-200"
              >
                Previous
              </button>
              <button
                disabled={page >= data.pages}
                onClick={() => setPage(page + 1)}
                className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800 text-slate-200"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
