import api from './api';

export const messageApi = {
  /**
   * Send a message through the onion routing system
   * @param {string} content - Message content (max 10000 chars)
   * @returns {Promise} API response with message ID and status
   */
  sendMessage: (content) => {
    return api.post('/message/send', { content });
  },

  /**
   * Get all messages for the current user
   * @returns {Promise} API response with messages array
   */
  getMessages: () => {
    return api.get('/messages');
  },

  /**
   * Get status of a specific message
   * @param {string} id - Message ID
   * @returns {Promise} API response with message status
   */
  getMessageStatus: (id) => {
    return api.get(`/message/${id}`);
  }
};
