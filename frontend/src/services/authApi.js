import api from './api';

export const authApi = {
  /**
   * Register a new user
   * @param {string} username - Username (3-30 chars)
   * @param {string} password - Password (8+ chars)
   * @returns {Promise} API response with token
   */
  register: (username, password) => {
    return api.post('/register', { username, password });
  },

  /**
   * Login with existing credentials
   * @param {string} username
   * @param {string} password
   * @returns {Promise} API response with token
   */
  login: (username, password) => {
    return api.post('/login', { username, password });
  }
};
