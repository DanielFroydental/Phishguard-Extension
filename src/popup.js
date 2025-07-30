/*
 * Popup Interface Manager - PhishGuard AI Extension
 * 
 * Manages the extension's popup interface for user interactions with the phishing detection system.
 * Handles manual scanning, API key configuration, scan history display, and settings management.
 * 
 * Key responsibilities:
 * - Provide intuitive interface for manual page scanning
 * - Manage API key validation and storage
 * - Display scan results with confidence levels and reasoning
 * - Maintain scan history and user preferences
 * - Handle modal dialogs for settings, help, and about information
 * - Coordinate with background service worker for scan operations
 */

/**
 * Main popup interface manager class that handles all user interactions.
 * Manages UI state, API communications, and user settings for the extension popup.
 */
class PopupManager {
    /**
     * Initialize the popup manager with default settings.
     * Sets up instance variables for API key, scanning state, and user preferences.
     */
    constructor() {
        this.apiKey = null;
        this.isScanning = false;
        this.scanHistory = [];
        this.confidenceThreshold = 70;
        this.init();
    }

    /**
     * Initialize the popup interface and load user data.
     * Sets up event listeners, loads stored settings, and prepares the UI.
     */
    async init() {
        await this.loadStoredData();
        this.setupEventListeners();
        this.updateUI();
        this.updateHistoryUI();
    }

    /**
     * Load stored user data from Chrome storage.
     * Retrieves API key, scan history, and confidence threshold settings.
     */
    async loadStoredData() {
        try {
            const result = await chrome.storage.sync.get(['geminiApiKey', 'scanHistory', 'confidenceThreshold']);
            this.apiKey = result.geminiApiKey || null;
            this.confidenceThreshold = result.confidenceThreshold || 70;
            this.scanHistory = result.scanHistory || [];
        } catch (error) {
            console.error('Error loading stored data:', error);
        }
    }

    /**
     * Set up event listeners for popup interface elements.
     * Attaches click handlers to buttons and navigation links.
     */
    setupEventListeners() {
        document.getElementById('scan-button').addEventListener('click', () => this.scanCurrentPage());
        
        document.getElementById('settings-link').addEventListener('click', (e) => {
            e.preventDefault();
            this.showSettings();
        });
        document.getElementById('help-link').addEventListener('click', (e) => {
            e.preventDefault();
            this.showHelp();
        });
        document.getElementById('about-link').addEventListener('click', (e) => {
            e.preventDefault();
            this.showAbout();
        });
    }

    /**
     * Save and validate user's Gemini API key.
     * Performs validation, testing, and secure storage of the API key.
     */
    async saveApiKey() {
        const apiKeyInput = document.getElementById('api-key');
        const apiKey = apiKeyInput.value.trim();

        if (!apiKey || apiKey === '••••••••••••••••') {
            this.showNotification('Please enter a valid API key', 'error', 4000);
            return;
        }

        const validation = this.validateApiKey(apiKey);
        if (!validation.valid) {
            this.showNotification(validation.error, 'error', 4000);
            return;
        }

        try {
            const testResult = await this.testApiKey(apiKey);
            if (!testResult.valid) {
                this.showNotification(testResult.error, 'error', 4000);
                return;
            }
            await chrome.storage.sync.set({ geminiApiKey: apiKey });
            this.apiKey = apiKey;
            apiKeyInput.value = '••••••••••••••••'; // Hide key after saving
            this.updateUI();
            this.showNotification('API key saved successfully!', 'success');
        } catch (error) {
            console.error('Error saving API key:', error);
            this.showNotification('Failed to save API key', 'error', 4000);
        }
    }

    /**
     * Update popup UI based on current API key status.
     * Enables/disables scan button and updates status indicators.
     */
    updateUI() {
        const scanButton = document.getElementById('scan-button');
        const statusText = document.getElementById('status-text');
        const statusDot = document.getElementById('status-dot');

        this.resetLogoBackground();

        if (this.apiKey) {
            scanButton.disabled = false;
            statusText.textContent = 'Ready to scan';
            statusDot.style.backgroundColor = '#4CAF50';
        } else {
            scanButton.disabled = true;
            statusText.textContent = 'API key required - Configure in Settings';
            statusDot.style.backgroundColor = '#ff9800';
        }
    }

    /**
     * Initiate phishing scan of the current active tab.
     * Coordinates with background script to analyze page content using AI.
     */
    async scanCurrentPage() {
        if (this.isScanning) return; // Prevent multiple simultaneous scans

        if (!this.apiKey) {
            this.showNotification('Please set your Gemini API key first', 'error', 4000);
            return;
        }

        this.isScanning = true;
        this.showLoading(true);

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab) {
                throw new Error('No active tab found');
            }

            // Send scan request to background service worker
            const response = await chrome.runtime.sendMessage({
                action: 'scanPage',
                tabId: tab.id,
                url: tab.url,
                scanSource: 'popup'
            });
            if (response.error) {
                throw new Error(response.error);
            }
            this.displayResults(response.result);
            this.saveToHistory(response.result);

        } catch (error) {
            console.error('Error scanning page:', error);
            let errorMessage = 'Scan failed';
            if (error.message.includes('Cannot access')) {
                errorMessage = 'Cannot scan this type of page. It is restricted by Chrome.';
            } else if (error.message.includes('Failed to extract')) {
                errorMessage = 'Unable to read page content. Try refreshing the page.';
            } else if (error.message.includes('API')) {
                errorMessage = 'API error. Please check your API key.';
            } else {
                errorMessage = `Scan failed: ${error.message}`;
            }
            
            this.showNotification(errorMessage, 'error', 5000);
        } finally {
            this.isScanning = false;
            this.showLoading(false);
        }
    }

    /**
     * Display scan results in the popup interface.
     * Updates UI with verdict, confidence level, reasoning, and visual indicators.
     */
    displayResults(result) {
        // Get UI elements for result display
        const resultsSection = document.getElementById('results-section');
        const resultCard = document.getElementById('result-card');
        const verdict = document.getElementById('verdict');
        const confidence = document.getElementById('confidence');
        const analyzedUrl = document.getElementById('analyzed-url');
        const reasoningList = document.getElementById('reasoning-list');
        const warningIndicator = document.getElementById('warning-indicator');
        const logoIcon = document.getElementById('logo-icon');

        // Determine result classification for styling
        let resultClass = result.verdict.toLowerCase();
        
        // Handle uncertain legitimate results (low confidence)
        if (result.verdict.toLowerCase() === 'legitimate' && result.confidence < this.confidenceThreshold) {
            resultClass = 'uncertain';
        }

        // Update UI elements with scan results
        verdict.textContent = result.verdict;
        verdict.className = `verdict ${resultClass}`;
        resultCard.className = `result-card ${resultClass}`;
        
        const confidenceElement = confidence;
        confidenceElement.textContent = `${Math.round(result.confidence)}%`;

        if (result.confidence >= this.confidenceThreshold) {
          confidenceElement.style.color =
            result.verdict.toLowerCase() === "legitimate" ? "#4CAF50" : "#f44336";
        } else {
          confidenceElement.style.color = "#ff9800";
        }
        
        this.updateLogoBackground(logoIcon, result);
        
        if (result.verdict.toLowerCase() === 'phishing' && result.confidence >= 80) {
            this.showNotification('High-confidence phishing detected! Check the banner on the webpage for details.', 'error', 3000);
        }
        
        if (result.verdict.toLowerCase() === 'legitimate' && result.confidence < this.confidenceThreshold) {
            warningIndicator.classList.remove('hidden');
        } else {
            warningIndicator.classList.add('hidden');
        }
        
        analyzedUrl.textContent = result.url;
        
        reasoningList.innerHTML = '';
        result.reasoning.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            reasoningList.appendChild(li);
        });

        resultsSection.style.display = 'block';
    }

    /**
     * Save scan result to history.
     * Stores the URL, domain, verdict, confidence, and timestamp in the scan history.
     */
    async saveToHistory(result) {
        const historyItem = {
            url: result.url,
            domain: new URL(result.url).hostname,
            verdict: result.verdict,
            confidence: result.confidence,
            timestamp: Date.now()
        };

        this.scanHistory.unshift(historyItem);
        this.scanHistory = this.scanHistory.slice(0, 10);

        try {
            await chrome.storage.sync.set({ scanHistory: this.scanHistory });
            this.updateHistoryUI();
        } catch (error) {
            console.error('Error saving to history:', error);
        }
    }

    /**
     * Update scan history display in the popup interface.
     * Renders list of recent scans with domains and verdicts.
     */
    updateHistoryUI() {
        const historyContainer = document.getElementById('scan-history');
        
        if (this.scanHistory.length === 0) {
            historyContainer.innerHTML = '<p class="empty-state">No recent scans</p>';
            return;
        }

        historyContainer.innerHTML = '';
        
        this.scanHistory.forEach(item => {
            const historyItem = document.createElement('div');
            historyItem.className = 'history-item';
            
            const domain = document.createElement('span');
            domain.className = 'domain';
            domain.textContent = item.domain;
            
            const result = document.createElement('span');
            result.className = `result ${item.verdict.toLowerCase()}`;
            result.textContent = item.verdict;
            
            historyItem.appendChild(domain);
            historyItem.appendChild(result);
            historyContainer.appendChild(historyItem);
        });
    }
    
    resetLogoBackground() {
        const logoIcon = document.getElementById('logo-icon');
        if (logoIcon) {
            logoIcon.classList.remove('logo-safe', 'logo-warning', 'logo-danger', 'logo-neutral');
            logoIcon.classList.add('logo-neutral');
        }
        this.resetToolbarIcon();
    }

    resetToolbarIcon() {
        try {
            chrome.action.setBadgeText({ text: '' });
            chrome.action.setBadgeBackgroundColor({ color: '#00000000' });
            chrome.action.setTitle({ title: 'PhishGuard AI - Click to scan current page' });
        } catch (error) {
            console.error('Error resetting toolbar icon:', error);
        }
    }
 
    /**
     * Show loading indicator during scans.
     * Displays a loading section and disables the scan button while processing.
     */
    showLoading(show) {
        const loadingSection = document.getElementById('loading-section');
        const scanButton = document.getElementById('scan-button');
        
        if (show) {
            loadingSection.style.display = 'block';
            scanButton.disabled = true;
            scanButton.textContent = 'Analyzing...';
        } else {
            loadingSection.style.display = 'none';
            scanButton.disabled = !this.apiKey;
            scanButton.innerHTML = '<span class="button-icon">🔍</span>Analyze Page';
        }
    }

    /**
     * Update logo background based on scan result.
     * Applies appropriate CSS classes to indicate scan status visually.
     */
    updateLogoBackground(logoIcon, result) {
        logoIcon.classList.remove('logo-safe', 'logo-warning', 'logo-danger', 'logo-neutral');
        
        const verdict = result.verdict.toLowerCase();
        const confidence = result.confidence;
        
        if (verdict === 'phishing') {
            logoIcon.classList.add('logo-danger');
        } else if (verdict === 'legitimate') {
            if (confidence >= this.confidenceThreshold) {
                logoIcon.classList.add('logo-safe');
            } else {
                logoIcon.classList.add('logo-warning');
            }
        } else {
            logoIcon.classList.add('logo-neutral');
        }
    }

    /**
     * Display a notification message in the popup.
     */
    showNotification(message, type = 'info', duration = 3000) {
        const existingNotification = document.querySelector('.popup-notification');
        if (existingNotification) {
            existingNotification.remove();
        }

        const notification = document.createElement('div');
        notification.className = `popup-notification ${type}`;
        notification.innerHTML = `
            <span class="notification-icon">${this.getNotificationIcon(type)}</span>
            <span class="notification-message">${message}</span>
            <button class="notification-close">✕</button>
        `;

        const closeButton = notification.querySelector('.notification-close');
        const closeNotification = () => {
            if (notification.parentElement) {
                notification.classList.add('fade-out');
                setTimeout(() => {
                    if (notification.parentElement) {
                        notification.remove();
                    }
                }, 300);
            }
        };
        closeButton.addEventListener('click', closeNotification);

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 10);

        setTimeout(() => {
            closeNotification();
        }, duration);
    }

    getNotificationIcon(type) {
        const icons = {
            'info': 'ℹ',
            'success': '✓',
            'warning': '⚠',
            'error': '!'
        };
        return icons[type] || icons['info'];
    }

    /**
     * Validate Gemini API key format.
     * Checks key length, prefix, and character validity.
     */
    validateApiKey(apiKey) {
        if (!apiKey || apiKey.length < 30) {
            return { valid: false, error: 'API key too short' };
        }
        
        if (!apiKey.startsWith('AIza')) {
            return { valid: false, error: 'Invalid API key format' };
        }
        
        if (apiKey.includes(' ') || apiKey.includes('\n')) {
            return { valid: false, error: 'API key contains invalid characters' };
        }
        
        return { valid: true };
    }

    /**
     * Test API key with Gemini service to verify it works.
     * Attempts connection with multiple model types for compatibility.
     */
    async testApiKey(apiKey) {
        const models = ['gemini-2.5-flash-lite', 'gemini-1.5-pro', 'gemini-pro'];
        
        for (const model of models) {
            try {
                const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        contents: [{
                            parts: [{ text: 'Say "API test successful" if you can read this.' }]
                        }],
                        generationConfig: {
                            temperature: 0.1,
                            maxOutputTokens: 50
                        }
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
                    return { valid: true, model: model, response: content };
                } else {
                    continue;
                }
            } catch (error) {
                continue;
            }
        }
        
        return { 
            valid: false, 
            error: 'API key failed with all available models' 
        };
    }

    /**
     * Display settings modal for API configuration and preferences.
     * Creates modal dialog with API key input, confidence threshold slider, and data management.
     */
    showSettings() {
        this.createModal('Settings', `
            <div class="settings-content">
                <h4>API Configuration</h4>
                <div class="setting-item">
                    <label for="modal-api-key">Gemini API Key:</label>
                    <div class="input-group">
                        <input type="password" id="modal-api-key" placeholder="Enter your API key" value="${this.apiKey ? '••••••••••••••••' : ''}">
                        <button id="save-api-key-btn" class="primary-button">Save</button>
                    </div>
                    <div id="api-status" class="api-status">${this.apiKey ? '<span class="status-success">✓ API key configured</span>' : '<span class="status-error">⚠ API key not configured</span>'}</div>
                    <p class="help-text">Get your API key from <a href="https://makersuite.google.com/app/apikey" target="_blank">Google AI Studio</a></p>
                </div>

                <h4>Scanning Preferences</h4>
                <div class="setting-item">
                    <label for="confidence-threshold">Minimum confidence threshold: <span id="threshold-value">${this.confidenceThreshold}%</span></label>
                    <div class="slider-container">
                        <span class="slider-label">50%</span>
                        <input type="range" id="confidence-threshold" min="50" max="90" value="${this.confidenceThreshold}" class="confidence-slider">
                        <span class="slider-label">90%</span>
                    </div>
                    <p class="help-text">Lower values = more alerts for uncertain sites. Higher values = fewer alerts, only high-confidence threats.</p>
                </div>

                <h4>Data & Privacy</h4>
                <div class="setting-item">
                    <button id="clear-history-btn" class="secondary-button">Clear Scan History</button>
                    <p class="help-text">Remove all stored scan results</p>
                </div>
            </div>
        `, () => {
        });

        document.getElementById('clear-history-btn').addEventListener('click', () => {
            this.clearScanHistory();
        });

        const thresholdSlider = document.getElementById('confidence-threshold');
        const thresholdValue = document.getElementById('threshold-value');
        
        thresholdSlider.addEventListener('input', (e) => {
            const value = e.target.value;
            thresholdValue.textContent = `${value}%`;
        });

        thresholdSlider.addEventListener('change', async (e) => {
            const newThreshold = parseInt(e.target.value);
            try {
                await chrome.storage.sync.set({ confidenceThreshold: newThreshold });
                this.confidenceThreshold = newThreshold;
                this.showNotification(`Confidence threshold updated to ${newThreshold}%`, 'success');
            } catch (error) {
                console.error('Error saving confidence threshold:', error);
                this.showNotification('Failed to save confidence threshold', 'error', 4000);
            }
        });

        document.getElementById('save-api-key-btn').addEventListener('click', async () => {
            const apiKeyInput = document.getElementById('modal-api-key');
            const apiKey = apiKeyInput.value.trim();

            if (!apiKey || apiKey === '••••••••••••••••') {
                this.showNotification('Please enter a valid API key', 'error', 4000);
                return;
            }

            const validation = this.validateApiKey(apiKey);
            if (!validation.valid) {
                this.showNotification(validation.error, 'error', 4000);
                return;
            }

            try {
                const testResult = await this.testApiKey(apiKey);
                if (!testResult.valid) {
                    this.showNotification(testResult.error, 'error', 4000);
                    return;
                }

                await chrome.storage.sync.set({ geminiApiKey: apiKey });
                this.apiKey = apiKey;
                apiKeyInput.value = '••••••••••••••••';
                
                document.getElementById('api-status').innerHTML = '<span class="status-success">✓ API key configured and validated</span>';
                
                this.updateUI();
                this.showNotification('API key saved successfully!', 'success');
            } catch (error) {
                console.error('Error saving API key:', error);
                this.showNotification('Failed to save API key', 'error', 4000);
            }
        });

        document.getElementById('modal-api-key').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                document.getElementById('save-api-key-btn').click();
            }
        });
    }

    /**
     * Display help modal with usage instructions and troubleshooting.
     * Provides comprehensive guide for using the extension effectively.
     */
    showHelp() {
        this.createModal('Help & Support', `
            <div class="help-content">
                <h4>Getting Started</h4>
                <ol>
                    <li><strong>API Setup:</strong> Get your free API key from <a href="https://makersuite.google.com/app/apikey" target="_blank">Google AI Studio</a></li>
                    <li><strong>Manual Scan:</strong> Click "Analyze Page" to scan the current webpage</li>
                    <li><strong>Right-Click Scan:</strong> Right-click on any page and select "Scan page for phishing"</li>
                    <li><strong>Adjust Threshold:</strong> Use the confidence slider in Settings to control sensitivity</li>
                </ol>

                <h4>Understanding Results</h4>
                <div class="result-explanation">
                    <div class="verdict-example safe">✅ LEGITIMATE</div>
                    <p>Website appears safe with high confidence</p>
                    
                    <div class="verdict-example suspicious">⚠️ SUSPICIOUS</div>
                    <p>Website has some concerning elements - proceed with caution</p>
                    
                    <div class="verdict-example danger">🚨 PHISHING</div>
                    <p>High likelihood of phishing - avoid entering personal information</p>
                </div>

                <h4>Tips for Safe Browsing</h4>
                <ul>
                    <li>Always verify URLs before entering sensitive information</li>
                    <li>Look for HTTPS (secure) connections</li>
                    <li>Be cautious of urgent or threatening messages</li>
                    <li>When in doubt, navigate to the official website directly</li>
                    <li>Adjust confidence threshold: Lower = more alerts, Higher = fewer alerts</li>
                </ul>

                <h4>Troubleshooting</h4>
                <p><strong>Scan not working?</strong> Check your API key and internet connection</p>
                <p><strong>False positives?</strong> AI analysis isn't perfect - use your judgment</p>
                <p><strong>Slow scans?</strong> Large pages may take longer to analyze</p>
                <p><strong>Need a fresh start?</strong> Clear scan history in Settings</p>

                <h4>Contact Support</h4>
                <p>Found a bug or have suggestions? <a href="mailto:support@phishguard.ai">Contact us</a></p>
            </div>
        `);
    }

    /**
     * Display about modal with extension information and credits.
     * Shows version, features, privacy policy, and acknowledgments.
     */
    showAbout() {
        this.createModal('About PhishGuard AI', `
            <div class="about-content">
                <div class="logo-section">
                    <img src="icons/icon48.png" alt="PhishGuard AI" class="about-logo">
                    <h3>PhishGuard AI</h3>
                    <p class="version">Version 1.0.0</p>
                </div>

                <div class="description">
                    <p>PhishGuard AI is a Chrome extension that uses Google's Gemini AI to detect phishing websites in real-time, helping protect you from online scams and malicious websites.</p>
                </div>

                <div class="features">
                    <h4>Key Features</h4>
                    <ul>
                        <li>🔍 Real-time phishing detection</li>
                        <li>🤖 Powered by Google Gemini AI</li>
                        <li>⚡ Instant analysis results</li>
                        <li>🛡️ Context menu scanning</li>
                        <li>📊 Detailed threat analysis</li>
                    </ul>
                </div>

                <div class="privacy">
                    <h4>Privacy & Security</h4>
                    <p>Your privacy matters. PhishGuard AI:</p>
                    <ul>
                        <li>Only sends page content to Google's Gemini API for analysis</li>
                        <li>Does not store or transmit personal data</li>
                        <li>Your API key is stored locally in Chrome</li>
                        <li>No tracking or analytics</li>
                    </ul>
                </div>

                <div class="credits">
                    <h4>Credits</h4>
                    <p>Built with ❤️ using:</p>
                    <ul>
                        <li>Google Gemini AI</li>
                        <li>Chrome Extensions API</li>
                        <li>Modern web technologies</li>
                        <li>
                            Made by the PhishGuard AI team:
                            <ul>
                                <li>Daniel Froydental</li>
                                <li>Noga Porat</li>
                            </ul>
                        </li>
                    </ul>
                </div>


                <div class="legal">
                    <p class="copyright">© 2025 PhishGuard AI. All rights reserved.</p>
                    <p class="disclaimer">This tool is provided as-is. Always use your best judgment when browsing the web.</p>
                </div>
            </div>
        `);
    }

    /**
     * Create and display modal dialog with specified content.
     * Handles modal lifecycle, event listeners, and cleanup.
     */
    createModal(title, content, onClose = null) {
        const existingModal = document.querySelector('.modal-overlay');
        if (existingModal) {
            existingModal.remove();
        }

        const modalHTML = `
            <div class="modal-overlay">
                <div class="modal">
                    <div class="modal-header">
                        <h3>${title}</h3>
                        <button class="modal-close">✕</button>
                    </div>
                    <div class="modal-body">
                        ${content}
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);

        const modal = document.querySelector('.modal-overlay');
        const closeBtn = document.querySelector('.modal-close');

        const closeModal = () => {
            if (onClose) onClose();
            modal.remove();
        };

        closeBtn.addEventListener('click', closeModal);
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
    }

    /**
     * Clear scan history and update UI.
     * Resets scan history in storage and refreshes the history display.
     */
    async clearScanHistory() {
        try {
            const clearButton = document.getElementById('clear-history-btn');
            const originalText = clearButton.textContent;
            clearButton.textContent = 'Clearing...';
            clearButton.disabled = true;
            
            await chrome.storage.sync.set({ scanHistory: [] });
            this.scanHistory = [];
            this.updateHistoryUI();
            
            clearButton.textContent = '✓ Cleared';
            clearButton.style.background = 'linear-gradient(135deg, #10b981, #059669)';
            clearButton.style.color = 'white';
            
            this.showNotification('Scan history cleared successfully', 'success');
            
            setTimeout(() => {
                clearButton.textContent = originalText;
                clearButton.disabled = false;
                clearButton.style.background = '';
                clearButton.style.color = '';
            }, 2000);
            
        } catch (error) {
            console.error('Error clearing history:', error);
            this.showNotification('Failed to clear history', 'error', 4000);
            
            const clearButton = document.getElementById('clear-history-btn');
            clearButton.textContent = 'Clear Scan History';
            clearButton.disabled = false;
        }
    }
}

// Initialize popup manager when DOM content is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PopupManager();
});
