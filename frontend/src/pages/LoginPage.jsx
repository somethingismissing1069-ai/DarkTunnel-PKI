import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(username, password);
      navigate('/dashboard');
    } catch (err) {
      // Generic error message - never reveal which field is wrong
      setError('Invalid credentials. Please check your username and password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 relative">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-dark-900 via-dark-800 to-dark-700"></div>
      <div className="absolute bottom-1/3 left-1/4 w-64 h-64 bg-cyber-cyan/10 rounded-full blur-3xl"></div>

      <div className="relative z-10 w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-block mb-4">
            <div className="w-12 h-12 bg-gradient-to-br from-cyber-cyan to-cyber-purple rounded-xl flex items-center justify-center mx-auto">
              <span className="text-dark-900 font-bold">DT</span>
            </div>
          </Link>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyber-cyan to-cyber-purple bg-clip-text text-transparent">
            Welcome Back
          </h1>
          <p className="text-white/50 mt-2">Access the secure network</p>
        </div>

        {/* Form */}
        <div className="glass-card p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="p-3 bg-danger/10 border border-danger/30 rounded-lg text-danger text-sm">
                {error}
              </div>
            )}

            <div>
              <label className="block text-sm text-white/70 mb-2">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="input-field"
                placeholder="Enter username"
                autoComplete="username"
                required
              />
            </div>

            <div>
              <label className="block text-sm text-white/70 mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-field"
                placeholder="Enter password"
                autoComplete="current-password"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-dark-900 border-t-transparent rounded-full animate-spin"></div>
                  Authenticating...
                </span>
              ) : (
                'Login'
              )}
            </button>
          </form>

          <p className="text-center text-white/50 text-sm mt-6">
            Don't have an account?{' '}
            <Link to="/register" className="text-cyber-cyan hover:underline">
              Register
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
