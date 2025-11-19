
/**
 * Popup Script
 * Handles extension popup interface
 */

const API_BASE_URL = 'http://localhost:8000/api';

// Load stats on popup open
document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  setupEventListeners();
});

// Load statistics
function loadStats() {
  chrome.runtime.sendMessage({ action: 'getStats' }, (response) => {
    if (response && response.stats) {
      document.getElementById('urlsScanned').textContent = response.stats.urlsScanned || 0;
      document.getElementById('threatsBlocked').textContent = response.stats.threatsBlocked || 0;
    }
  });
}

// Setup event listeners
function setupEventListeners() {
  // Analyze button
  document.getElementById('analyzeBtn').addEventListener('click', handleAnalyze);
  
  // Enter key in input
  document.getElementById('quickAnalyzeInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      handleAnalyze();
    }
  });
  
  // Open dashboard
  document.getElementById('openDashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:3000' });
  });
  
  // Rescan page
  document.getElementById('rescanPage').addEventListener('click', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.tabs.sendMessage(tabs[0].id, { action: 'rescanPage' }, (response) => {
        if (response && response.success) {
          showNotification('Page rescanned successfully!', 'success');
        }
      });
    });
  });
}

// Handle analyze button click
async function handleAnalyze() {
  const input = document.getElementById('quickAnalyzeInput');
  const url = input.value.trim();
  
  if (!url) {
    showNotification('Please enter a URL', 'error');
    return;
  }
  
  // Show loading state
  setLoadingState(true);
  hideResult();
  
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    if (!response.ok) {
      throw new Error('Analysis failed');
    }
    
    const result = await response.json();
    displayResult(result);
    
  } catch (error) {
    console.error('Analysis error:', error);
    showNotification('Analysis failed. Check if backend is running.', 'error');
  } finally {
    setLoadingState(false);
  }
}

// Display analysis result
function displayResult(result) {
  const resultSection = document.getElementById('resultSection');
  const emoji = document.getElementById('resultEmoji');
  const level = document.getElementById('resultLevel');
  const score = document.getElementById('resultScore');
  const barFill = document.getElementById('resultBarFill');
  const message = document.getElementById('resultMessage');
  
  // Determine emoji and color
  let emojiIcon, color;
  if (result.risk_score >= 70) {
    emojiIcon = '🚨';
    color = '#ef4444';
  } else if (result.risk_score >= 40) {
    emojiIcon = '⚠️';
    color = '#f59e0b';
  } else if (result.risk_score >= 20) {
    emojiIcon = 'ℹ️';
    color = '#3b82f6';
  } else {
    emojiIcon = '✅';
    color = '#10b981';
  }
  
  // Update UI
  emoji.textContent = emojiIcon;
  level.textContent = result.risk_level;
  level.style.color = color;
  score.textContent = result.risk_score;
  barFill.style.width = `${result.risk_score}%`;
  barFill.style.backgroundColor = color;
  message.textContent = result.recommendation;
  
  // Show result section
  resultSection.style.display = 'block';
  
  // Animate
  setTimeout(() => {
    resultSection.classList.add('fade-in');
  }, 10);
}

// Hide result section
function hideResult() {
  const resultSection = document.getElementById('resultSection');
  resultSection.style.display = 'none';
  resultSection.classList.remove('fade-in');
}

// Set loading state
function setLoadingState(loading) {
  const btn = document.getElementById('analyzeBtn');
  const btnText = document.getElementById('btnText');
  const btnLoader = document.getElementById('btnLoader');
  const input = document.getElementById('quickAnalyzeInput');
  
  if (loading) {
    btn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.style.display = 'inline-block';
    input.disabled = true;
  } else {
    btn.disabled = false;
    btnText.style.display = 'inline';
    btnLoader.style.display = 'none';
    input.disabled = false;
  }
}

// Show notification
function showNotification(message, type) {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  // Remove after 3 seconds
  setTimeout(() => {
    notification.remove();
  }, 3000);
}

console.log('🛡️ Fraud Detection Popup Loaded');
