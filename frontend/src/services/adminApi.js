import api from './api';

export const adminApi = {
  /**
   * Get audit logs (admin only)
   * @param {Object} filters - Optional filters
   * @param {string} filters.eventType - Filter by event type
   * @returns {Promise} API response with logs array
   */
  getLogs: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.eventType) {
      params.append('eventType', filters.eventType);
    }
    return api.get(`/admin/logs?${params.toString()}`);
  }
};
