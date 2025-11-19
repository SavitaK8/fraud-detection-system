
/**
 * Application Constants
 */

export const RISK_LEVELS = {
  HIGH: 'HIGH RISK',
  MEDIUM: 'MEDIUM RISK',
  LOW: 'LOW RISK',
  SAFE: 'SAFE',
};

export const RISK_COLORS = {
  'HIGH RISK': 'red',
  'MEDIUM RISK': 'yellow',
  'LOW RISK': 'blue',
  'SAFE': 'green',
};

export const ANALYSIS_TYPES = {
  URL: 'url',
  EMAIL: 'email',
  PHONE: 'phone',
  IMAGE: 'image',
};

export const TABS = [
  {
    id: 'url',
    label: 'URL Analysis',
    placeholder: 'Enter URL (e.g., https://paypa1.com/verify)',
  },
  {
    id: 'email',
    label: 'Email/Text',
    placeholder: 'Paste email content or text message...',
  },
  {
    id: 'phone',
    label: 'Phone Number',
    placeholder: 'Enter phone number (e.g., +91 1860 123 4567)',
  },
  {
    id: 'image',
    label: 'Image Analysis',
    placeholder: 'Upload image for OCR analysis',
  },
];

export const SAMPLE_PHISHING_URL = 'https://paypa1.com/verify';
export const SAMPLE_PHISHING_EMAIL = 'URGENT! Your account has been suspended. Click here immediately to verify your bank details before it expires today!';
export const SAMPLE_PHISHING_PHONE = '+91 1860 123 4567';

export const PROJECT_INFO = {
  title: 'Real-Time Fraud Detection System',
  subtitle: 'AI-Powered Multi-Layer Security Analysis',
  version: '1.0.0',
  team: ['Savita Kumari', 'Ruchir Jain', 'Shivam Singh', 'Sonu Kumar'],
  college: 'ITS Engineering College',
  session: '2025-2026',
};