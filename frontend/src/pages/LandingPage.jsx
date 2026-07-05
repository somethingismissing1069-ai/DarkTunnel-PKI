import React from 'react';
import { Link } from 'react-router-dom';

function LandingPage() {
  const features = [
    {
      title: 'PKI & Certificates',
      description: 'Internal Certificate Authority with X.509 certificates for users and relay nodes. Full certificate lifecycle management.',
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      )
    },
    {
      title: 'Onion Routing',
      description: 'Simulated Tor-like 3-node relay system. Messages are wrapped in layers of encryption, each peeled by successive nodes.',
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
        </svg>
      )
    },
    {
      title: 'E2E Encryption',
      description: 'AES-256-GCM symmetric encryption with RSA key wrapping. Messages are encrypted end-to-end with authenticated encryption.',
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      )
    },
    {
      title: 'Forward Secrecy',
      description: 'Ephemeral session keys ensure past communications remain secure even if long-term keys are compromised.',
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
      )
    }
  ];

  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Animated gradient background */}
      <div className="absolute inset-0 bg-gradient-to-br from-dark-900 via-dark-800 to-dark-700"></div>
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyber-cyan/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyber-purple/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
      </div>

      {/* Content */}
      <div className="relative z-10">
        {/* Hero Section */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
          <div className="text-center">
            {/* Logo */}
            <div className="flex justify-center mb-8">
              <div className="w-20 h-20 bg-gradient-to-br from-cyber-cyan to-cyber-purple rounded-2xl flex items-center justify-center shadow-lg shadow-cyber-cyan/20">
                <span className="text-dark-900 font-bold text-2xl">DT</span>
              </div>
            </div>

            {/* Title */}
            <h1 className="text-5xl sm:text-7xl font-bold mb-4">
              <span className="bg-gradient-to-r from-cyber-cyan via-cyber-purple to-cyber-pink bg-clip-text text-transparent">
                DarkTunnel PKI
              </span>
            </h1>
            <p className="text-xl sm:text-2xl text-white/60 mb-4 font-light">
              Anonymous Communication System
            </p>
            <p className="text-white/40 max-w-2xl mx-auto mb-12">
              Secure messaging through simulated onion routing with PKI-based identity verification,
              hybrid encryption, and forward secrecy.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                to="/register"
                className="btn-primary text-lg px-8 py-3 w-full sm:w-auto text-center"
              >
                Get Started
              </Link>
              <Link
                to="/login"
                className="px-8 py-3 border border-white/20 text-white/80 rounded-lg hover:bg-white/5 hover:border-white/40 transition-all text-lg w-full sm:w-auto text-center"
              >
                Login
              </Link>
            </div>
          </div>
        </div>

        {/* Features Grid */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-20">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, index) => (
              <div
                key={index}
                className="glass-card p-6 hover:bg-white/10 transition-all duration-300 hover:border-cyber-cyan/30 group"
              >
                <div className="text-cyber-cyan mb-4 group-hover:scale-110 transition-transform">
                  {feature.icon}
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">{feature.title}</h3>
                <p className="text-white/50 text-sm leading-relaxed">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* System Architecture Diagram */}
        <div className="max-w-4xl mx-auto px-4 pb-20">
          <div className="glass-card p-8 text-center">
            <h2 className="text-2xl font-bold bg-gradient-to-r from-cyber-cyan to-cyber-purple bg-clip-text text-transparent mb-6">
              System Architecture
            </h2>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 text-sm font-mono">
              <div className="px-4 py-2 bg-cyber-cyan/10 border border-cyber-cyan/30 rounded-lg text-cyber-cyan">
                Client (React)
              </div>
              <span className="text-white/30">&rarr;</span>
              <div className="px-4 py-2 bg-cyber-purple/10 border border-cyber-purple/30 rounded-lg text-cyber-purple">
                API (Express)
              </div>
              <span className="text-white/30">&rarr;</span>
              <div className="px-4 py-2 bg-cyber-pink/10 border border-cyber-pink/30 rounded-lg text-cyber-pink">
                Relay A &rarr; B &rarr; C
              </div>
              <span className="text-white/30">&rarr;</span>
              <div className="px-4 py-2 bg-success/10 border border-success/30 rounded-lg text-success">
                Output
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LandingPage;
