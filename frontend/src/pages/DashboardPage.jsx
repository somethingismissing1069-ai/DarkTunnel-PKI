import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { messageApi } from '../services/messageApi';

function DashboardPage() {
  const { user } = useAuth();
  const [stats, setStats] = useState({ sent: 0, delivered: 0, failed: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await messageApi.getMessages();
      const messages = response.data?.messages || response.data || [];
      const sent = messages.length;
      const delivered = messages.filter((m) => m.status === 'delivered').length;
      const failed = messages.filter((m) => m.status === 'failed' || m.status === 'invalid_signature').length;
      setStats({ sent, delivered, failed });
    } catch {
      // If API not available, show zeros
      setStats({ sent: 0, delivered: 0, failed: 0 });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Welcome */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">
          Welcome back, <span className="bg-gradient-to-r from-cyber-cyan to-cyber-purple bg-clip-text text-transparent">{user?.username || 'Agent'}</span>
        </h1>
        <p className="text-white/50 mt-2">Your secure communication dashboard</p>
      </div>

      {/* Certificate Status */}
      <div className="glass-card p-6 mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">Certificate Status</h2>
            <p className="text-white/50 text-sm mt-1">Your PKI identity certificate</p>
          </div>
          <span className="inline-flex items-center space-x-2 px-4 py-2 bg-success/10 border border-success/30 rounded-full">
            <span className="w-2 h-2 bg-success rounded-full animate-pulse"></span>
            <span className="text-success text-sm font-medium">Valid</span>
          </span>
        </div>
        <div className="mt-4 p-3 bg-dark-700/50 rounded-lg">
          <p className="text-xs font-mono text-white/40">
            Subject: CN={user?.username || 'user'}, O=DarkTunnel, OU=Users
          </p>
          <p className="text-xs font-mono text-white/40 mt-1">
            Issuer: CN=DarkTunnel CA, O=DarkTunnel PKI
          </p>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="glass-card p-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-white/50 text-sm">Messages Sent</span>
            <svg className="w-5 h-5 text-cyber-cyan" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </div>
          <p className="text-3xl font-bold text-white">
            {loading ? <span className="animate-pulse">...</span> : stats.sent}
          </p>
        </div>

        <div className="glass-card p-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-white/50 text-sm">Delivered</span>
            <svg className="w-5 h-5 text-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <p className="text-3xl font-bold text-success">
            {loading ? <span className="animate-pulse">...</span> : stats.delivered}
          </p>
        </div>

        <div className="glass-card p-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-white/50 text-sm">Failed</span>
            <svg className="w-5 h-5 text-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </div>
          <p className="text-3xl font-bold text-danger">
            {loading ? <span className="animate-pulse">...</span> : stats.failed}
          </p>
        </div>
      </div>

      {/* Navigation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Link
          to="/send"
          className="glass-card p-6 hover:bg-white/10 transition-all duration-300 hover:border-cyber-cyan/30 group"
        >
          <div className="flex items-center space-x-4">
            <div className="w-12 h-12 bg-cyber-cyan/10 rounded-xl flex items-center justify-center group-hover:bg-cyber-cyan/20 transition-colors">
              <svg className="w-6 h-6 text-cyber-cyan" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
              </svg>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white group-hover:text-cyber-cyan transition-colors">
                Send Message
              </h3>
              <p className="text-white/50 text-sm">Encrypt and route through relay nodes</p>
            </div>
          </div>
        </Link>

        <Link
          to="/tracking"
          className="glass-card p-6 hover:bg-white/10 transition-all duration-300 hover:border-cyber-purple/30 group"
        >
          <div className="flex items-center space-x-4">
            <div className="w-12 h-12 bg-cyber-purple/10 rounded-xl flex items-center justify-center group-hover:bg-cyber-purple/20 transition-colors">
              <svg className="w-6 h-6 text-cyber-purple" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white group-hover:text-cyber-purple transition-colors">
                Track Messages
              </h3>
              <p className="text-white/50 text-sm">View message history and delivery status</p>
            </div>
          </div>
        </Link>
      </div>
    </div>
  );
}

export default DashboardPage;
