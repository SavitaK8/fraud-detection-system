
/**
 * Background Service Worker
 * Handles context menus, notifications, and background tasks
 */

// API Configuration
const API_BASE_URL = 'https://fraud-detection-system-production-1758.up.railway.app/api';

// Statistics
let stats = {
  urlsScanned: 0,
  threatsBlocked: 0,
  lastScan: null
};

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ Fraud Detection Extension Installed');
  
  // Create context menu
  chrome.contextMenus.create({
    id: 'analyze-link',
    title: 'Analyze Link for Threats',
    contexts: ['link']
  });
  
  chrome.contextMenus.create({
    id: 'analyze-selection',
    title: 'Analyze Selected Text',
    contexts: ['selection']
  });
  
  // Load stats from storage
  chrome.storage.local.get(['stats'], (result) => {
    if (result.stats) {
      stats = result.stats;
    }
  });
  
  // Show welcome notification
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: 'Fraud Detection Active',
    message: 'Real-time protection enabled. Stay safe online!'
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'analyze-link') {
    analyzeURL(info.linkUrl, tab);
  } else if (info.menuItemId === 'analyze-selection') {
    analyzeText(info.selectionText, tab);
  }
});

// Analyze URL function
async function analyzeURL(url, tab) {
  try {
    console.log('🔍 Analyzing URL:', url);
    
    const response = await fetch(`${API_BASE_URL}/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    const result = await response.json();
    
    // Update stats
    stats.urlsScanned++;
    if (result.risk_score >= 70) {
      stats.threatsBlocked++;
    }
    stats.lastScan = new Date().toISOString();
    chrome.storage.local.set({ stats });
    
    // Show notification
    showNotification(result);
    
    // Block if high risk
    if (result.risk_score >= 70) {
      chrome.tabs.update(tab.id, { url: 'about:blank' });
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: '🚨 THREAT BLOCKED',
        message: `High-risk URL detected and blocked!\nRisk Score: ${result.risk_score}/100`,
        priority: 2
      });
    }
    
  } catch (error) {
    console.error('❌ Analysis failed:', error);
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Analysis Failed',
      message: 'Could not connect to fraud detection server.'
    });
  }
}

// Analyze text function
async function analyzeText(text, tab) {
  try {
    console.log('🔍 Analyzing Text:', text.substring(0, 50) + '...');
    
    const response = await fetch(`${API_BASE_URL}/analyze/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: text })
    });
    
    const result = await response.json();
    
    // Show notification
    showNotification(result);
    
  } catch (error) {
    console.error('❌ Analysis failed:', error);
  }
}

// Show notification based on risk level
function showNotification(result) {
  let emoji = '✅';
  let priority = 0;
  
  if (result.risk_score >= 70) {
    emoji = '🚨';
    priority = 2;
  } else if (result.risk_score >= 40) {
    emoji = '⚠️';
    priority = 1;
  }
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: `${emoji} ${result.risk_level}`,
    message: `Risk Score: ${result.risk_score}/100\n${result.recommendation}`,
    priority: priority
  });
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeURL') {
    analyzeURL(request.url, sender.tab).then(() => {
      sendResponse({ success: true });
    });
    return true; // Keep channel open for async response
  }
  
  if (request.action === 'getStats') {
    sendResponse({ stats });
    return true;
  }
});

// Periodic clipboard check (optional - commented out for privacy)
/*
setInterval(() => {
  navigator.clipboard.readText().then(text => {
    // Check if text looks like URL
    if (text.startsWith('http://') || text.startsWith('https://')) {
      analyzeURL(text, null);
    }
  }).catch(() => {
    // Clipboard access denied
  });
}, 30000); // Check every 30 seconds
*/

console.log('🛡️ Fraud Detection Background Service Running');
