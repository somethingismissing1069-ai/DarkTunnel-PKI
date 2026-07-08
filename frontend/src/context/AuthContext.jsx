import React, { createContext, useContext, useState, useEffect } from 'react';
import { authApi } from '../services/authApi';

const AuthContext = createContext(null);

// Simple JWT decode (payload only - no verification needed on client)
function decodeToken(token) {
  try {
    const payload = token.split('.')[1];
    const decoded = JSON.parse(atob(payload));
    return decoded;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('darktunnel_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // On mount, check localStorage for existing token
    const storedToken = localStorage.getItem('darktunnel_token');
    if (storedToken) {
      const decoded = decodeToken(storedToken);
      if (decoded && decoded.exp * 1000 > Date.now()) {
        setUser(decoded);
        setToken(storedToken);
      } else {
        // Token expired - clear it
        localStorage.removeItem('darktunnel_token');
        setToken(null);
        setUser(null);
      }
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    const response = await authApi.login(username, password);
    const { token: newToken } = response.data;
    localStorage.setItem('darktunnel_token', newToken);
    setToken(newToken);
    const decoded = decodeToken(newToken);
    setUser(decoded);
    return response;
  };

  const register = async (username, password) => {
    const response = await authApi.register(username, password);
    const { token: newToken } = response.data;
    if (newToken) {
      localStorage.setItem('darktunnel_token', newToken);
      setToken(newToken);
      const decoded = decodeToken(newToken);
      setUser(decoded);
    }
    return response;
  };

  const logout = () => {
    localStorage.removeItem('darktunnel_token');
    setToken(null);
    setUser(null);
  };

  const isAuthenticated = !!token && !!user;
  const isAdmin = user?.role === 'admin';

  const value = {
    user,
    token,
    login,
    logout,
    register,
    isAuthenticated,
    isAdmin,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
