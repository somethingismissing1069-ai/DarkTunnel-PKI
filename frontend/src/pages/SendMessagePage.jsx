import React, { useState } from 'react';
import { messageApi } from '../services/messageApi';

const MAX_CHARS = 10000;

// Simulated progress stages for onion routing visualization
const PROGRESS_STAGES = [
  { label: 'Signing message...', icon: '\u270D\uFE0F' },
  { label: 'Encrypting Layer 3 (Node C)...', icon: '\uD83D\uDD10' },
  { label: 'Encrypting Layer 2 (Node B)...', icon: '\uD83D\uDD10' },
  { label: 'Encrypting Layer 1 (Node A)...', icon: '\uD83D\uDD10' },
  { label: 'Routing through relay network...', icon: '\uD83C\uDF10' }
];

function SendMessagePage() {
  const [content, setContent] = useState('');
  const [sending, setSending] = useState(false);
  const [currentStage, setCurrentStage] = useState(-1);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const simulateProgress = () => {
    return new Promise((resolve) => {
      let stage = 0;
      const interval = setInterval(() => {
        setCurrentStage(stage);
        stage++;
        if (stage >= PROGRESS_STAGES.length) {
          clearInterval(interval);
          resolve();
        }
      }, 600);
    });
  };

  const handleSend = async (e) => {
    e.preventDefault();
    if (!content.trim()) return;

    setError('');
    setResult(null);
    setSending(true);
    setCurrentStage(0);

    try {
      // Run progress animation and API call simultaneously
      const [, response] = await Promise.all([
        simulateProgress(),
        messageApi.sendMessage(content)
      ]);

      setResult({
        success: true,
        message: 'Message delivered successfully through relay network!',
        data: response.data
      });
      setContent('');
    } catch (err) {
      const errMsg = err.response?.data?.error || err.response?.data?.message || 'Failed to send message';
      setResult({
        success: false,
        message: errMsg
      });
    } finally {
      setSending(false);
      setCurrentStage(-1);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold bg-gradient-to-r from-cyber-cyan to-cyber-purple bg-clip-text text-transparent">
          Send Encrypted Message
        </h1>
        <p className="text-white/50 mt-2">
          Your message will be encrypted in layers and routed through 3 relay nodes
        </p>
      </div>

      {/* Message Form */}
      <div className="glass-card p-6 mb-6">
        <form onSubmit={handleSend}>
          <div className="mb-4">
            <label className="block text-sm text-white/70 mb-2">Message Content</label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value.slice(0, MAX_CHARS))}
              className="input-field min-h-[200px] resize-y font-mono text-sm"
              placeholder="Enter your message here. It will be encrypted and routed through the onion network..."
              disabled={sending}
              required
            />
            <div className="flex justify-end mt-2">
              <span className={`text-xs ${content.length >= MAX_CHARS ? 'text-danger' : 'text-white/30'}`}>
                {content.length}/{MAX_CHARS}
              </span>
            </div>
          </div>

          <button
            type="submit"
            disabled={sending || !content.trim()}
            className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {sending ? 'Processing...' : 'Send Through Relay Network'}
          </button>
        </form>
      </div>

      {/* Progress Indicator */}
      {sending && (
        <div className="glass-card p-6 mb-6">
          <h3 className="text-lg font-semibold text-white mb-4">Onion Routing in Progress</h3>
          <div className="space-y-3">
            {PROGRESS_STAGES.map((stage, index) => (
              <div
                key={index}
                className={`flex items-center space-x-3 p-3 rounded-lg transition-all duration-300 ${
                  index === currentStage
                    ? 'bg-cyber-cyan/10 border border-cyber-cyan/30'
                    : index < currentStage
                    ? 'bg-success/5 border border-success/20'
                    : 'opacity-30'
                }`}
              >
                <span className="text-lg">{stage.icon}</span>
                <span className={`text-sm ${
                  index === currentStage ? 'text-cyber-cyan' : index < currentStage ? 'text-success' : 'text-white/50'
                }`}>
                  {stage.label}
                </span>
                {index === currentStage && (
                  <div className="ml-auto w-4 h-4 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin"></div>
                )}
                {index < currentStage && (
                  <span className="ml-auto text-success">\u2713</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Result */}
      {result && (
        <div className={`glass-card p-6 border ${
          result.success ? 'border-success/30' : 'border-danger/30'
        }`}>
          <div className="flex items-start space-x-3">
            <span className="text-2xl">
              {result.success ? '\u2705' : '\u274C'}
            </span>
            <div>
              <h3 className={`font-semibold ${result.success ? 'text-success' : 'text-danger'}`}>
                {result.success ? 'Delivered!' : 'Error'}
              </h3>
              <p className="text-white/70 text-sm mt-1">{result.message}</p>
              {result.data?.messageId && (
                <p className="text-xs font-mono text-white/40 mt-2">
                  Message ID: {result.data.messageId}
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default SendMessagePage;
