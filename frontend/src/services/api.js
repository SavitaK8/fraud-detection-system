
/**
 * API Service - Connects React Frontend to FastAPI Backend
 */

import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://fraud-detection-system-production-1758.up.railway.app/';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    console.log(`🔵 API Request: ${config.method.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('🔴 API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    console.log(`🟢 API Response: ${response.config.url}`, response.data);
    return response;
  },
  (error) => {
    console.error('🔴 API Response Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// Analyze URL
export const analyzeURL = async (url) => {
  try {
    const response = await api.post('/analyze/url', { url });
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'URL analysis failed' };
  }
};

// Analyze Email
export const analyzeEmail = async (content, senderEmail = null) => {
  try {
    const response = await api.post('/analyze/email', {
      content,
      sender_email: senderEmail,
    });
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Email analysis failed' };
  }
};

// Analyze Phone
export const analyzePhone = async (phoneNumber) => {
  try {
    const response = await api.post('/analyze/phone', {
      phone_number: phoneNumber,
    });
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Phone analysis failed' };
  }
};

// Analyze Image
export const analyzeImage = async (imageFile) => {
  try {
    const formData = new FormData();
    formData.append('file', imageFile);
    
    const response = await api.post('/analyze/image', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Image analysis failed' };
  }
};

// Get Stats
export const getStats = async () => {
  try {
    const response = await api.get('/stats');
    return response.data;
  } catch (error) {
    throw error.response?.data || { error: 'Failed to fetch stats' };
  }
};

export default api;
