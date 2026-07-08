import React from 'react';

/**
 * Status badge component for message tracking
 * Displays color-coded badges based on message status
 */
function StatusBadge({ status }) {
  const statusConfig = {
    delivered: {
      label: 'Delivered',
      icon: '\u2713',
      className: 'bg-success/20 text-success border-success/30'
    },
    pending: {
      label: 'Pending',
      icon: '\u23F3',
      className: 'bg-warning/20 text-warning border-warning/30'
    },
    failed: {
      label: 'Failed',
      icon: '\u2717',
      className: 'bg-danger/20 text-danger border-danger/30'
    },
    invalid_signature: {
      label: 'Signature Invalid',
      icon: '\u2717',
      className: 'bg-danger/20 text-danger border-danger/30'
    }
  };

  const config = statusConfig[status?.toLowerCase()] || statusConfig.pending;

  return (
    <span className={`inline-flex items-center space-x-1 px-3 py-1 rounded-full text-xs font-medium border ${config.className}`}>
      <span>{config.icon}</span>
      <span>{config.label}</span>
    </span>
  );
}

export default StatusBadge;
