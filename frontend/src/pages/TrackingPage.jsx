import React, { useState, useEffect } from 'react';
import { messageApi } from '../services/messageApi';
import StatusBadge from '../components/StatusBadge';

function TrackingPage() {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchMessages();
  }, []);

  const fetchMessages = async () => {
    try {
      const response = await messageApi.getMessages();
      const data = response.data?.messages || response.data || [];
      setMessages(Array.isArray(data) ? data : []);
    } catch (err) {
      setError('Failed to load messages. Please try again.');
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

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyber-cyan to-cyber-purple bg-clip-text text-transparent">
            Message Tracking
          </h1>
          <p className="text-white/50 mt-2">Monitor your message delivery status</p>
        </div>
        <button
          onClick={fetchMessages}
          className="px-4 py-2 border border-white/20 text-white/70 rounded-lg hover:bg-white/5 transition-all text-sm"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="p-4 bg-danger/10 border border-danger/30 rounded-lg text-danger text-sm mb-6">
          {error}
        </div>
      )}

      {messages.length === 0 ? (
        /* Empty state */
        <div className="glass-card p-12 text-center">
          <svg className="w-16 h-16 text-white/20 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
          </svg>
          <h3 className="text-lg font-semibold text-white/70 mb-2">No messages sent yet</h3>
          <p className="text-white/40 text-sm">Send your first encrypted message through the relay network</p>
        </div>
      ) : (
        /* Messages Table */
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left py-4 px-6 text-sm font-medium text-white/50">ID</th>
                  <th className="text-left py-4 px-6 text-sm font-medium text-white/50">Status</th>
                  <th className="text-left py-4 px-6 text-sm font-medium text-white/50">Date</th>
                </tr>
              </thead>
              <tbody>
                {messages.map((msg, index) => (
                  <tr
                    key={msg.id || index}
                    className="border-b border-white/5 hover:bg-white/5 transition-colors"
                  >
                    <td className="py-4 px-6">
                      <span className="text-xs font-mono text-white/60">
                        {msg.id ? (typeof msg.id === 'string' && msg.id.length > 12 ? `${msg.id.slice(0, 12)}...` : msg.id) : `#${index + 1}`}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <StatusBadge status={msg.status} />
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-sm text-white/60">
                        {formatDate(msg.created_at || msg.createdAt || msg.timestamp)}
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

export default TrackingPage;
