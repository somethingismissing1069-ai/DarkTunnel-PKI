import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { adminApi } from '../services/adminApi';

function AdminLogsPage() {
  const { isAdmin } = useAuth();
  const navigate = useNavigate();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterType, setFilterType] = useState('');

  // Event types for filter dropdown
  const eventTypes = [
    '',
    'AUTH_LOGIN',
    'AUTH_REGISTER',
    'AUTH_FAILED',
    'MESSAGE_SENT',
    'MESSAGE_DELIVERED',
    'MESSAGE_FAILED',
    'CERT_GENERATED',
    'CERT_REVOKED',
    'RELAY_PROCESSED',
    'SIGNATURE_VERIFIED',
    'SIGNATURE_FAILED'
  ];

  useEffect(() => {
    if (!isAdmin) {
      navigate('/dashboard');
      return;
    }
    fetchLogs();
  }, [isAdmin, navigate, filterType]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const filters = filterType ? { eventType: filterType } : {};
      const response = await adminApi.getLogs(filters);
      const data = response.data?.logs || response.data || [];
      setLogs(Array.isArray(data) ? data : []);
    } catch (err) {
      setError('Failed to load audit logs.');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateStr) => {
    try {
      return new Date(dateStr).toLocaleString();
    } catch {
      return dateStr || 'N/A';
    }
  };

  const getEventBadgeColor = (eventType) => {
    if (!eventType) return 'text-white/50 bg-white/5 border-white/10';
    if (eventType.includes('FAILED') || eventType.includes('REVOKED')) {
      return 'text-danger bg-danger/10 border-danger/20';
    }
    if (eventType.includes('AUTH') || eventType.includes('LOGIN')) {
      return 'text-cyber-cyan bg-cyber-cyan/10 border-cyber-cyan/20';
    }
    if (eventType.includes('MESSAGE')) {
      return 'text-cyber-purple bg-cyber-purple/10 border-cyber-purple/20';
    }
    if (eventType.includes('CERT') || eventType.includes('SIGNATURE')) {
      return 'text-success bg-success/10 border-success/20';
    }
    return 'text-warning bg-warning/10 border-warning/20';
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-8 gap-4">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyber-cyan to-cyber-purple bg-clip-text text-transparent">
            Audit Logs
          </h1>
          <p className="text-white/50 mt-2">System event monitoring (Admin only)</p>
        </div>

        {/* Filter */}
        <div className="flex items-center space-x-3">
          <label className="text-sm text-white/50">Filter:</label>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-dark-700/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyber-cyan"
          >
            <option value="">All Events</option>
            {eventTypes.filter(Boolean).map((type) => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-danger/10 border border-danger/30 rounded-lg text-danger text-sm mb-6">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin"></div>
        </div>
      ) : logs.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <h3 className="text-lg font-semibold text-white/70 mb-2">No logs found</h3>
          <p className="text-white/40 text-sm">
            {filterType ? `No events matching "${filterType}"` : 'No audit events recorded yet'}
          </p>
        </div>
      ) : (
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left py-4 px-6 text-sm font-medium text-white/50">Event Type</th>
                  <th className="text-left py-4 px-6 text-sm font-medium text-white/50">Details</th>
                  <th className="text-left py-4 px-6 text-sm font-medium text-white/50">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log, index) => (
                  <tr
                    key={log.id || index}
                    className="border-b border-white/5 hover:bg-white/5 transition-colors"
                  >
                    <td className="py-4 px-6">
                      <span className={`inline-block px-2 py-1 rounded text-xs font-mono border ${getEventBadgeColor(log.event_type || log.eventType)}`}>
                        {log.event_type || log.eventType || 'UNKNOWN'}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-sm text-white/60 font-mono">
                        {typeof log.details === 'object' ? JSON.stringify(log.details) : (log.details || '-')}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-sm text-white/60">
                        {formatDate(log.timestamp || log.created_at || log.createdAt)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default AdminLogsPage;
