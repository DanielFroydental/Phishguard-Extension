/*
 * Popup Interface Manager - PhishGuard AI Extension
 * Manages the extension's popup interface for user interactions with the phishing detection system.
 */
class PopupManager {
    constructor() {
        this.apiKey = null;
        this.isScanning = false;
        this.scanHistory = [];
        this.selectedModel = 'flashLite';
        this.safeThreshold = 80; // Score above which sites are considered safe
        this.cautionThreshold = 50; // Score above which sites show caution warning
        this.init();
    }

    async init() {
        await this.loadStoredData();
        this.setupEventListeners();
        this.setupMessageListener();
        this.updateUI();
        this.updateHistoryUI();
    }

    // Listen for messages from background script
    // Listen for messages from background script
    setupMessageListener() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.action === 'showPopupNotification') {
                this.showNotification(request.message, request.type, 4000);
                sendResponse({ success: true });
            }
            return true;
        });
    }

    // Load user settings and scan history from Chrome storage
    // Load user settings and scan history from Chrome storage
    async loadStoredData() {
        try {
            const result = await chrome.storage.sync.get([
                'geminiApiKey', 
                'scanHistory', 
                'safeThreshold', 
                'cautionThreshold',
                'selectedModel'
            ]);
            this.apiKey = result.geminiApiKey || null;
            this.scanHistory = result.scanHistory || [];
            this.safeThreshold = result.safeThreshold || 80;
            this.cautionThreshold = result.cautionThreshold || 50;
            this.selectedModel = result.selectedModel || 'flashLite';
        } catch (error) {
            console.error('Error loading stored data:', error);
        }
    }

    // Set up event listeners for UI interactions
    // Set up event listeners for UI interactions
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

    // Save and validate API key
    // Save and validate API key
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

    // Update UI based on current state
    // Update UI based on current state
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

    // Initiate scan of current active tab
    // Initiate scan of current active tab
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

    // Display scan results in the popup interface
    displayResults(result) {
        // Get UI elements for result display
        const resultsSection = document.getElementById('results-section');
        const resultCard = document.getElementById('result-card');
        const verdict = document.getElementById('verdict');
        const confidence = document.getElementById('confidence');
        const analyzedUrl = document.getElementById('analyzed-url');
        const reasoningList = document.getElementById('reasoning-list');
        const warningIndicator = document.getElementById('warning-indicator');
        const legitimateIndicator = document.getElementById('legitimate-indicator');
        const phishingIndicator = document.getElementById('phishing-indicator');
        const logoIcon = document.getElementById('logo-icon');

        const score = result.legitimacyScore;
        
        // Determine result classification based on legitimacy score
        let resultClass, displayVerdict;
        if (score >= this.safeThreshold) { // 80-100: Safe/Legitimate
            resultClass = 'legitimate';
            displayVerdict = 'Legitimate';
        } else if (score >= this.cautionThreshold) { // 50-79: Caution/Uncertain
            resultClass = 'uncertain';
            displayVerdict = 'Uncertain';
        } else { // 0-49: Danger/Phishing
            resultClass = 'phishing';
            displayVerdict = 'Phishing';
        }

        // Update UI elements with scan results
        verdict.textContent = displayVerdict;
        verdict.className = `verdict ${resultClass}`;
        resultCard.className = `result-card ${resultClass}`;
        
        // Display the legitimacy score as percentage with clear label
        const confidenceElement = confidence;
        confidenceElement.innerHTML = `
            <div class="confidence-wrapper">
                <span class="confidence-label">Legitimacy</span>
                <span class="confidence-value">${Math.round(score)}%</span>
            </div>
        `;

        // Color code based on score ranges
        if (score >= this.safeThreshold) {
            confidenceElement.style.color = "#059669"; // Green for safe
        } else if (score >= this.cautionThreshold) {
            confidenceElement.style.color = "#d97706"; // Orange for caution
        } else {
            confidenceElement.style.color = "#dc2626"; // Red for danger
        }
        
        this.updateLogoBackground(logoIcon, { legitimacyScore: score, verdict: displayVerdict });
        
        // Show notification for high-risk phishing
        if (score < this.cautionThreshold) {
            this.showNotification('Phishing website detected! Check the banner on the webpage for details.', 'error', 3000);
        }
        
        // Show appropriate indicator based on score ranges
        if (score >= this.safeThreshold) {
            legitimateIndicator.classList.remove('hidden');
            warningIndicator.classList.add('hidden');
            phishingIndicator.classList.add('hidden');
        } else if (score >= this.cautionThreshold) {
            warningIndicator.classList.remove('hidden');
            legitimateIndicator.classList.add('hidden');
            phishingIndicator.classList.add('hidden');
        } else { // 0-49: Danger/Phishing
            phishingIndicator.classList.remove('hidden');
            warningIndicator.classList.add('hidden');
            legitimateIndicator.classList.add('hidden');
        }
        
        analyzedUrl.textContent = result.url;
        
        // Add model information if available
        const urlInfo = document.querySelector('.url-info');
        let modelInfo = urlInfo.querySelector('.model-info');
        if (!modelInfo) {
            modelInfo = document.createElement('div');
            modelInfo.className = 'model-info';
            urlInfo.appendChild(modelInfo);
        }
        
        if (result.modelDisplayName) {
            modelInfo.innerHTML = `<strong>Analyzed by:</strong> <span class="model-name">${result.modelDisplayName}</span>`;
            modelInfo.style.display = 'block';
        } else {
            modelInfo.style.display = 'none';
        }
        
        reasoningList.innerHTML = '';
        result.reasoning.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            reasoningList.appendChild(li);
        });

        resultsSection.style.display = 'block';
    }

    // Save scan result to history for future reference
    async saveToHistory(result) {
        const score = result.legitimacyScore;
        let verdict;
        if (score >= this.safeThreshold) {
            verdict = 'Legitimate';
        } else if (score >= this.cautionThreshold) {
            verdict = 'Uncertain';
        } else {
            verdict = 'Phishing';
        }

        const historyItem = {
            url: result.url,
            domain: new URL(result.url).hostname,
            verdict: verdict,
            legitimacyScore: score,
            timestamp: Date.now()
        };

        this.scanHistory.unshift(historyItem);
        this.scanHistory = this.scanHistory.slice(0, 10); // Keep only last 10 scans

        try {
            await chrome.storage.sync.set({ scanHistory: this.scanHistory });
            this.updateHistoryUI();
        } catch (error) {
            console.error('Error saving to history:', error);
        }
    }

    // Update the scan history display in the popup
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
    
    // Reset logo to neutral state
    resetLogoBackground() {
        const logoIcon = document.getElementById('logo-icon');
        if (logoIcon) {
            logoIcon.classList.remove('logo-safe', 'logo-warning', 'logo-danger', 'logo-neutral');
            logoIcon.classList.add('logo-neutral');
        }
        this.resetToolbarIcon();
    }

    // Reset extension toolbar badge
    resetToolbarIcon() {
        try {
            chrome.action.setBadgeText({ text: '' });
            chrome.action.setBadgeBackgroundColor({ color: '#00000000' });
            chrome.action.setTitle({ title: 'PhishGuard AI - Click to scan current page' });
        } catch (error) {
            console.error('Error resetting toolbar icon:', error);
        }
    }

    // Show/hide loading state during scan
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

    // Update logo background color based on scan result
    updateLogoBackground(logoIcon, result) {
        logoIcon.classList.remove('logo-safe', 'logo-warning', 'logo-danger', 'logo-neutral');
        
        const score = result.legitimacyScore;
        
        if (score >= this.safeThreshold) { // 80-100: Safe/Legitimate
            logoIcon.classList.add('logo-safe');
        } else if (score >= this.cautionThreshold) { // 50-79: Caution/Uncertain
            logoIcon.classList.add('logo-warning');
        } else { // 0-49: Danger/Phishing
            logoIcon.classList.add('logo-danger');
        }
    }

    // Display notification messages to user
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

    // Get appropriate icon for notification type
    getNotificationIcon(type) {
        const icons = {
            'info': 'ℹ',
            'success': '✓',
            'warning': '⚠',
            'error': '!'
        };
        return icons[type] || icons['info'];
    }

    // Validate API key format
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

    // Get human-readable model name for display
    getModelDisplayName(modelKey) {
        const displayNames = {
            'flashLite': 'Gemini 2.5 Flash Lite',
            'flash': 'Gemini 2.5 Flash',
            'pro': 'Gemini 2.5 Pro'
        };
        
        return displayNames[modelKey] || modelKey;
    }

    // Test specific Gemini model with API key
    async testSpecificModel(modelKey, apiKey) {
        const modelMap = {
            'flashLite': 'gemini-2.5-flash-lite',
            'flash': 'gemini-2.5-flash', 
            'pro': 'gemini-2.5-pro'
        };
        
        const modelName = modelMap[modelKey];
        if (!modelName) {
            return { valid: false, error: 'Unknown model type' };
        }
        
        try {
            const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: 'test' }] }],
                    generationConfig: { maxOutputTokens: 10 }
                })
            });

            if (response.ok) {
                return { valid: true };
            } else {
                const errorData = await response.json().catch(() => ({}));
                const errorMessage = errorData.error?.message || `HTTP ${response.status}`;
                
                if (response.status === 403) {
                    return { valid: false, error: 'API key does not have access to this model.' };
                } else if (response.status === 404) {
                    return { valid: false, error: 'Model not found or not available.' };
                } else {
                    return { valid: false, error: errorMessage };
                }
            }
        } catch (error) {
            return { valid: false, error: `Network error: ${error.message}` };
        }
    }

    // Test API key with all available models
    async testApiKey(apiKey) {
        const models = ['gemini-2.5-flash-lite', 'gemini-2.5-flash', 'gemini-2.5-pro'];
        
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

    // Show settings modal with configuration options
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
                
                <div class="setting-item">
                    <label for="model-select">AI Model:</label>
                    <select id="model-select">
                        <option value="flashLite">Gemini 2.5 Flash Lite (Fast & Cost-effective)</option>
                        <option value="flash">Gemini 2.5 Flash (Balanced Performance)</option>
                        <option value="pro">Gemini 2.5 Pro (Highest Quality)</option>
                    </select>
                    <p class="help-text">Choose your preferred AI model. Higher quality models provide better analysis but cost more.</p>
                </div>

                <h4>Legitimacy Score Thresholds</h4>
                <div class="setting-item">
                    <div class="threshold-controls">
                        <div class="threshold-setting">
                            <label for="safe-threshold">Safe Threshold: <span id="safe-threshold-value">${this.safeThreshold}%</span></label>
                            <div class="slider-container">
                                <span class="slider-label">70%</span>
                                <input type="range" id="safe-threshold" min="70" max="95" value="${this.safeThreshold}" class="threshold-slider safe">
                                <span class="slider-label">95%</span>
                            </div>
                            <p class="help-text">Sites scoring above this threshold are considered safe/legitimate</p>
                        </div>
                        
                        <div class="threshold-setting">
                            <label for="caution-threshold">Caution Threshold: <span id="caution-threshold-value">${this.cautionThreshold}%</span></label>
                            <div class="slider-container">
                                <span class="slider-label">30%</span>
                                <input type="range" id="caution-threshold" min="30" max="70" value="${this.cautionThreshold}" class="threshold-slider caution">
                                <span class="slider-label">70%</span>
                            </div>
                            <p class="help-text">Sites scoring above this threshold show caution warning</p>
                        </div>
                    </div>
                    
                    <div class="current-ranges">
                        <div class="range-display safe">
                            <span class="range-label" id="safe-range">${this.safeThreshold}-100%</span>
                            <span class="range-desc">Safe/Legitimate ✅</span>
                        </div>
                        <div class="range-display caution">
                            <span class="range-label" id="caution-range">${this.cautionThreshold}-${this.safeThreshold-1}%</span>
                            <span class="range-desc">Uncertain/Caution ⚠️</span>
                        </div>
                        <div class="range-display danger">
                            <span class="range-label" id="danger-range">0-${this.cautionThreshold-1}%</span>
                            <span class="range-desc">Danger/Phishing ❗️</span>
                        </div>
                    </div>
                    
                    <div class="threshold-actions">
                        <button id="reset-thresholds-btn" class="secondary-button">Reset to Defaults</button>
                    </div>
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

        // Threshold slider event listeners
        const safeThresholdSlider = document.getElementById('safe-threshold');
        const cautionThresholdSlider = document.getElementById('caution-threshold');
        const safeThresholdValue = document.getElementById('safe-threshold-value');
        const cautionThresholdValue = document.getElementById('caution-threshold-value');

        // Update display values as sliders move
        safeThresholdSlider.addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            safeThresholdValue.textContent = `${value}%`;
            this.updateRangeDisplays(value, this.cautionThreshold);
        });

        cautionThresholdSlider.addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            cautionThresholdValue.textContent = `${value}%`;
            this.updateRangeDisplays(this.safeThreshold, value);
        });

        // Save threshold changes
        safeThresholdSlider.addEventListener('change', async (e) => {
            const newThreshold = parseInt(e.target.value);
            // Ensure safe threshold is always higher than caution threshold
            if (newThreshold <= this.cautionThreshold) {
                e.target.value = this.cautionThreshold + 10;
                newThreshold = this.cautionThreshold + 10;
                safeThresholdValue.textContent = `${newThreshold}%`;
                this.showNotification('Safe threshold must be higher than caution threshold', 'warning', 3000);
            }
            try {
                await chrome.storage.sync.set({ safeThreshold: newThreshold });
                this.safeThreshold = newThreshold;
                this.updateRangeDisplays(newThreshold, this.cautionThreshold);
                this.showNotification(`Safe threshold updated to ${newThreshold}%`, 'success');
            } catch (error) {
                console.error('Error saving safe threshold:', error);
                this.showNotification('Failed to save safe threshold', 'error', 4000);
            }
        });

        cautionThresholdSlider.addEventListener('change', async (e) => {
            const newThreshold = parseInt(e.target.value);
            // Ensure caution threshold is always lower than safe threshold
            if (newThreshold >= this.safeThreshold) {
                e.target.value = this.safeThreshold - 10;
                newThreshold = this.safeThreshold - 10;
                cautionThresholdValue.textContent = `${newThreshold}%`;
                this.showNotification('Caution threshold must be lower than safe threshold', 'warning', 3000);
            }
            try {
                await chrome.storage.sync.set({ cautionThreshold: newThreshold });
                this.cautionThreshold = newThreshold;
                this.updateRangeDisplays(this.safeThreshold, newThreshold);
                this.showNotification(`Caution threshold updated to ${newThreshold}%`, 'success');
            } catch (error) {
                console.error('Error saving caution threshold:', error);
                this.showNotification('Failed to save caution threshold', 'error', 4000);
            }
        });

        // Reset thresholds button
        document.getElementById('reset-thresholds-btn').addEventListener('click', async () => {
            try {
                const defaultSafe = 80;
                const defaultCaution = 50;
                await chrome.storage.sync.set({ 
                    safeThreshold: defaultSafe, 
                    cautionThreshold: defaultCaution 
                });
                this.safeThreshold = defaultSafe;
                this.cautionThreshold = defaultCaution;
                
                // Update UI
                safeThresholdSlider.value = defaultSafe;
                cautionThresholdSlider.value = defaultCaution;
                safeThresholdValue.textContent = `${defaultSafe}%`;
                cautionThresholdValue.textContent = `${defaultCaution}%`;
                this.updateRangeDisplays(defaultSafe, defaultCaution);
                
                this.showNotification('Thresholds reset to defaults', 'success');
            } catch (error) {
                console.error('Error resetting thresholds:', error);
                this.showNotification('Failed to reset thresholds', 'error', 4000);
            }
        });

        // Set current model selection
        document.getElementById('model-select').value = this.selectedModel;

        // Threshold slider event listeners
        this.setupThresholdSliders();

        document.getElementById('reset-thresholds-btn').addEventListener('click', () => {
            this.resetThresholds();
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

        // Model selection event listener with validation
        document.getElementById('model-select').addEventListener('change', async (e) => {
            const selectedModel = e.target.value;
            const previousModel = this.selectedModel;
            
            // Don't test if selecting the same model
            if (selectedModel === previousModel) {
                return;
            }
            
            try {
                // First check if we have an API key
                if (!this.apiKey) {
                    this.showNotification('Please configure your API key first', 'error', 4000);
                    e.target.value = previousModel; // Revert dropdown
                    return;
                }
                
                // Show testing notification
                this.showNotification('Testing model access...', 'info', 2000);
                
                // Test the selected model
                const testResult = await this.testSpecificModel(selectedModel, this.apiKey);
                
                if (testResult.valid) {
                    // Model works, save the selection
                    await chrome.storage.sync.set({ selectedModel: selectedModel });
                    this.selectedModel = selectedModel;
                    this.showNotification(`Successfully switched to ${this.getModelDisplayName(selectedModel)}!`, 'success');
                } else {
                    // Model failed, revert to flash-lite
                    const fallbackModel = 'flashLite';
                    e.target.value = fallbackModel; // Revert dropdown
                    
                    // Save fallback model
                    await chrome.storage.sync.set({ selectedModel: fallbackModel });
                    this.selectedModel = fallbackModel;
                    
                    // Show informative error
                    this.showNotification(
                        `Access denied to ${this.getModelDisplayName(selectedModel)}. Reverted to Flash Lite. ${testResult.error || 'Your API key may not have access to this model.'}`,
                        'error',
                        6000
                    );
                }
            } catch (error) {
                console.error('Error testing model selection:', error);
                
                // Revert to previous model on any error
                e.target.value = previousModel;
                this.showNotification('Failed to test model access. Selection reverted.', 'error', 4000);
            }
        });
    }

    // Update range display labels when thresholds change
    updateRangeDisplays(safeThreshold, cautionThreshold) {
        const safeRange = document.getElementById('safe-range');
        const cautionRange = document.getElementById('caution-range');
        const dangerRange = document.getElementById('danger-range');
        
        if (safeRange) safeRange.textContent = `${safeThreshold}-100%`;
        if (cautionRange) cautionRange.textContent = `${cautionThreshold}-${safeThreshold-1}%`;
        if (dangerRange) dangerRange.textContent = `0-${cautionThreshold-1}%`;
    }

    // Show help modal with usage instructions
    showHelp() {
        this.createModal('Help & Support', `
            <div class="help-content">
                <h4>Getting Started</h4>
                <ol>
                    <li><strong>API Setup:</strong> Get your free API key from <a href="https://makersuite.google.com/app/apikey" target="_blank">Google AI Studio</a></li>
                    <li><strong>Manual Scan:</strong> Click "Analyze Page" to scan the current webpage</li>
                    <li><strong>Right-Click Scan:</strong> Right-click on any page and select "Scan page for phishing"</li>
                    <li><strong>Customize Thresholds:</strong> Adjust score thresholds in Settings to match your security preference</li>
                    <li><strong>View Results:</strong> Check the legitimacy score and detailed reasoning</li>
                </ol>

                <h4>Understanding Results</h4>
                <div class="result-explanation">
                    <div class="verdict-example safe">✅ LEGITIMATE (Safe threshold+)</div>
                    <p>Website appears safe with high legitimacy score</p>
                    
                    <div class="verdict-example suspicious">⚠️ UNCERTAIN (Between thresholds)</div>
                    <p>Website has mixed signals - proceed with caution</p>
                    
                    <div class="verdict-example danger">❗️ PHISHING (Below caution threshold)</div>
                    <p>High risk of phishing - avoid entering personal information</p>
                </div>

                <h4>Tips for Safe Browsing</h4>
                <ul>
                    <li>Always verify URLs before entering sensitive information</li>
                    <li>Look for HTTPS (secure) connections</li>
                    <li>Be cautious of urgent or threatening messages</li>
                    <li>When in doubt, navigate to the official website directly</li>
                    <li>Pay attention to the legitimacy score and reasoning provided</li>
                    <li>Adjust thresholds in Settings: Lower = more alerts, Higher = fewer alerts</li>
                </ul>

                <h4>Troubleshooting</h4>
                <p><strong>Scan not working?</strong> Check your API key and internet connection</p>
                <p><strong>False positives?</strong> AI analysis isn't perfect - use your judgment</p>
                <p><strong>Slow scans?</strong> Large pages may take longer to analyze</p>
                <p><strong>Need a fresh start?</strong> Clear scan history in Settings</p>

                <h4>Contact Support</h4>
                <p>Found a bug or have suggestions? Contact us at:</p>
                <p><a href="mailto:froydent@post.bgu.ac.il">froydent@post.bgu.ac.il</a> or <a href="mailto:nogapo@bgu.ac.il">nogapo@bgu.ac.il</a></p>
            </div>
        `);
    }

    // Show about modal with extension information
    showAbout() {
        this.createModal('About PhishGuard AI', `
            <div class="about-content">
                <div class="logo-section">
                    <img src="icons/icon48.png" alt="PhishGuard AI" class="about-logo">
                    <h3>PhishGuard AI</h3>
                    <p class="version">Version 1.0.0</p>
                </div>

                <div class="description">
                    <p>PhishGuard AI is a Chrome extension that uses Google's Gemini AI to detect phishing websites in real-time, providing a legitimacy score (0-100%) to help protect you from online scams and malicious websites.</p>
                </div>

                <div class="features">
                    <h4>Key Features</h4>
                    <ul>
                        <li>🔍 Real-time phishing detection</li>
                        <li>🤖 Powered by Google Gemini AI</li>
                        <li>📊 Legitimacy scoring (0-100%)</li>
                        <li>⚡ Instant analysis results</li>
                        <li>🛡️ Context menu scanning</li>
                        <li>📋 Detailed threat reasoning</li>
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

    // Set up threshold slider event listeners
    setupThresholdSliders() {
        const safeSlider = document.getElementById('safe-threshold');
        const cautionSlider = document.getElementById('caution-threshold');
        const safeValue = document.getElementById('safe-threshold-value');
        const cautionValue = document.getElementById('caution-threshold-value');

        // Update display values on input
        safeSlider.addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            safeValue.textContent = `${value}%`;
            this.updateRangeDisplays(value, this.cautionThreshold);
        });

        cautionSlider.addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            cautionValue.textContent = `${value}%`;
            this.updateRangeDisplays(this.safeThreshold, value);
        });

        // Save changes on release
        safeSlider.addEventListener('change', async (e) => {
            const newValue = parseInt(e.target.value);
            if (newValue <= this.cautionThreshold) {
                this.showNotification('Safe threshold must be higher than caution threshold', 'error', 4000);
                e.target.value = this.safeThreshold;
                safeValue.textContent = `${this.safeThreshold}%`;
                return;
            }
            await this.saveThreshold('safeThreshold', newValue);
        });

        cautionSlider.addEventListener('change', async (e) => {
            const newValue = parseInt(e.target.value);
            if (newValue >= this.safeThreshold) {
                this.showNotification('Caution threshold must be lower than safe threshold', 'error', 4000);
                e.target.value = this.cautionThreshold;
                cautionValue.textContent = `${this.cautionThreshold}%`;
                return;
            }
            await this.saveThreshold('cautionThreshold', newValue);
        });
    }

    // Save threshold setting to storage
    async saveThreshold(thresholdType, value) {
        try {
            const storageData = {};
            storageData[thresholdType] = value;
            await chrome.storage.sync.set(storageData);
            
            this[thresholdType] = value;
            this.updateRangeDisplays(this.safeThreshold, this.cautionThreshold);
            
            const thresholdName = thresholdType === 'safeThreshold' ? 'Safe' : 'Caution';
            this.showNotification(`${thresholdName} threshold updated to ${value}%`, 'success');
        } catch (error) {
            console.error('Error saving threshold:', error);
            this.showNotification('Failed to save threshold', 'error', 4000);
        }
    }

    // Reset thresholds to default values
    async resetThresholds() {
        try {
            const defaultSafe = 80;
            const defaultCaution = 50;
            
            await chrome.storage.sync.set({
                safeThreshold: defaultSafe,
                cautionThreshold: defaultCaution
            });
            
            this.safeThreshold = defaultSafe;
            this.cautionThreshold = defaultCaution;
            
            // Update UI elements
            const safeSlider = document.getElementById('safe-threshold');
            const cautionSlider = document.getElementById('caution-threshold');
            const safeValue = document.getElementById('safe-threshold-value');
            const cautionValue = document.getElementById('caution-threshold-value');
            
            if (safeSlider) safeSlider.value = defaultSafe;
            if (cautionSlider) cautionSlider.value = defaultCaution;
            if (safeValue) safeValue.textContent = `${defaultSafe}%`;
            if (cautionValue) cautionValue.textContent = `${defaultCaution}%`;
            
            this.updateRangeDisplays(defaultSafe, defaultCaution);
            this.showNotification('Thresholds reset to defaults', 'success');
        } catch (error) {
            console.error('Error resetting thresholds:', error);
            this.showNotification('Failed to reset thresholds', 'error', 4000);
        }
    }

    // Create modal dialog for settings, help, and about
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

    // Clear all scan history from storage
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
