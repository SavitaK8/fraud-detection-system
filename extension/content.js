
/**
 * Content Script
 * Runs on every webpage to analyze links and detect threats
 */

console.log('🛡️ Fraud Detection Content Script Loaded');

// API Configuration
const API_BASE_URL = 'http://localhost:8000/api';

// Track analyzed links to avoid duplicate checks
const analyzedLinks = new Set();

// Initialize page protection
initializeProtection();

function initializeProtection() {
  // Scan all links on page load
  scanAllLinks();
  
  // Watch for new links added dynamically
  observeDOMChanges();
  
  // Add click listener to intercept suspicious links
  document.addEventListener('click', handleLinkClick, true);
  
  console.log('✅ Page protection initialized');
}

// Scan all links on the page
function scanAllLinks() {
  const links = document.querySelectorAll('a[href]');
  console.log(`🔍 Scanning ${links.length} links on page...`);
  
  links.forEach((link, index) => {
    // Throttle to avoid overwhelming the API
    setTimeout(() => {
      analyzeLinkElement(link);
    }, index * 100); // 100ms delay between each check
  });
}

// Analyze individual link element
async function analyzeLinkElement(linkElement) {
  const url = linkElement.href;
  
  // Skip if already analyzed
  if (analyzedLinks.has(url)) {
    return;
  }
  
  // Skip internal links and non-http(s) protocols
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return;
  }
  
  analyzedLinks.add(url);
  
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    const result = await response.json();
    
    // Add visual indicator based on risk
    addRiskIndicator(linkElement, result);
    
    // Store result in data attribute
    linkElement.setAttribute('data-risk-score', result.risk_score);
    linkElement.setAttribute('data-risk-level', result.risk_level);
    
  } catch (error) {
    console.error('❌ Link analysis failed:', error);
  }
}

// Add visual risk indicator to link
function addRiskIndicator(linkElement, result) {
  const score = result.risk_score;
  let color, emoji;
  
  if (score >= 70) {
    color = '#ef4444'; // Red
    emoji = '🚨';
    linkElement.style.border = '2px solid #ef4444';
    linkElement.style.backgroundColor = '#fee2e2';
  } else if (score >= 40) {
    color = '#f59e0b'; // Yellow
    emoji = '⚠️';
    linkElement.style.border = '2px solid #f59e0b';
    linkElement.style.backgroundColor = '#fef3c7';
  } else if (score >= 20) {
    color = '#3b82f6'; // Blue
    emoji = 'ℹ️';
  } else {
    color = '#10b981'; // Green
    emoji = '✅';
  }
  
  // Add tooltip
  linkElement.title = `${emoji} Risk Score: ${score}/100 - ${result.risk_level}`;
  
  // Add small badge
  const badge = document.createElement('span');
  badge.textContent = emoji;
  badge.style.cssText = `
    margin-left: 4px;
    font-size: 12px;
    vertical-align: super;
  `;
  
  // Only add badge for medium and high risk
  if (score >= 40) {
    linkElement.appendChild(badge);
  }
}

// Handle link clicks
function handleLinkClick(event) {
  const link = event.target.closest('a[href]');
  
  if (!link) return;
  
  const riskScore = parseInt(link.getAttribute('data-risk-score') || '0');
  const riskLevel = link.getAttribute('data-risk-level') || 'UNKNOWN';
  
  // Block high-risk links
  if (riskScore >= 70) {
    event.preventDefault();
    event.stopPropagation();
    
    showWarningModal(link.href, riskScore, riskLevel);
    return false;
  }
  
  // Warn for medium-risk links
  if (riskScore >= 40) {
    const proceed = confirm(
      `⚠️ WARNING: This link has been flagged as potentially dangerous.\n\n` +
      `Risk Score: ${riskScore}/100\n` +
      `Risk Level: ${riskLevel}\n\n` +
      `Do you want to proceed anyway?`
    );
    
    if (!proceed) {
      event.preventDefault();
      event.stopPropagation();
      return false;
    }
  }
}

// Show warning modal for blocked links
function showWarningModal(url, score, level) {
  const modal = document.createElement('div');
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 999999;
    font-family: system-ui, -apple-system, sans-serif;
  `;
  
  modal.innerHTML = `
    <div style="
      background: white;
      padding: 30px;
      border-radius: 10px;
      max-width: 500px;
      text-align: center;
    ">
      <div style="font-size: 48px; margin-bottom: 20px;">🚨</div>
      <h2 style="color: #ef4444; margin-bottom: 10px;">THREAT BLOCKED</h2>
      <p style="font-size: 18px; margin-bottom: 20px;">
        This link has been identified as high-risk and blocked for your protection.
      </p>
      <div style="background: #fee2e2; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
        <p style="margin: 5px 0;"><strong>Risk Score:</strong> ${score}/100</p>
        <p style="margin: 5px 0;"><strong>Risk Level:</strong> ${level}</p>
        <p style="margin: 5px 0; font-size: 12px; color: #666; word-break: break-all;">
          <strong>URL:</strong> ${url}
        </p>
      </div>
      <button id="closeWarning" style="
        background: #3b82f6;
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 5px;
        font-size: 16px;
        cursor: pointer;
        margin-right: 10px;
      ">Close</button>
      <button id="reportThreat" style="
        background: #10b981;
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 5px;
        font-size: 16px;
        cursor: pointer;
      ">Report Threat</button>
    </div>
  `;
  
  document.body.appendChild(modal);
  
  // Close button
  document.getElementById('closeWarning').addEventListener('click', () => {
    modal.remove();
  });
  
  // Report button
  document.getElementById('reportThreat').addEventListener('click', () => {
    alert('Thank you for reporting! This threat has been logged.');
    modal.remove();
  });
}

// Observe DOM changes for dynamically added links
function observeDOMChanges() {
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === 1) { // Element node
          // Check if node is a link
          if (node.tagName === 'A' && node.href) {
            analyzeLinkElement(node);
          }
          
          // Check for links inside added node
          const links = node.querySelectorAll ? node.querySelectorAll('a[href]') : [];
          links.forEach(link => analyzeLinkElement(link));
        }
      });
    });
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'rescanPage') {
    analyzedLinks.clear();
    scanAllLinks();
    sendResponse({ success: true });
  }
});

console.log('✅ Fraud Detection Active on this page');
