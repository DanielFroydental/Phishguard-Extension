/**
 * PhishGuard AI Background Service Worker
 * Handles all background tasks for the PhishGuard extension,
 * including API communication, scan management, and user data storage.
 */

const GEMINI_CONFIG = {
    models: {
        pro: 'gemini-2.5-pro',
        flash: 'gemini-2.5-flash',
        flashLite: 'gemini-2.5-flash-lite'
    },
    modelInfo: {
        'gemini-2.5-pro': { name: 'Gemini 2.5 Pro', cost: 'high', description: 'Highest quality for complex analysis' },
        'gemini-2.5-flash': { name: 'Gemini 2.5 Flash', cost: 'medium', description: 'Balanced performance and cost' },
        'gemini-2.5-flash-lite': { name: 'Gemini 2.5 Flash Lite', cost: 'low', description: 'Fast and cost-effective' }
    },
    fallbackOrder: ['pro', 'flash', 'flashLite'],
    defaultModel: 'flashLite',
    apiSettings: {
        baseUrl: 'https://generativelanguage.googleapis.com/v1beta',
        temperature: 0.1,
        maxOutputTokens: 1024
    }
};

class PhishGuardBackground {
    constructor() {
        this.geminiApiKey = null;
        this.safeThreshold = 80;
        this.cautionThreshold = 50;
        this.scannedTabs = new Map();
        this.selectedModel = GEMINI_CONFIG.defaultModel;
        this.currentModel = null;
        this.init();
    }

    async init() {
        await this.loadSettings();
        this.setupEventListeners();
        this.setupContextMenu();
    }

    async loadSettings() {
        try {
            const result = await chrome.storage.sync.get([
                'geminiApiKey', 
                'safeThreshold', 
                'cautionThreshold',
                'selectedModel'
            ]);
            this.geminiApiKey = result.geminiApiKey || null;
            this.safeThreshold = result.safeThreshold || 80;
            this.cautionThreshold = result.cautionThreshold || 50;
            this.selectedModel = result.selectedModel || GEMINI_CONFIG.defaultModel;
            this.currentModel = GEMINI_CONFIG.models[this.selectedModel];
        } catch (error) {
            console.error('Error loading settings:', error);
        }
    }

    setupEventListeners() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true;
        });

        chrome.storage.onChanged.addListener((changes, namespace) => {
            this.handleStorageChange(changes, namespace);
        });

        chrome.tabs.onActivated.addListener((activeInfo) => {
            this.handleTabActivated(activeInfo);
        });

        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            this.handleTabUpdated(tabId, changeInfo, tab);
        });
    }

    setupContextMenu() {
        chrome.contextMenus.create({
            id: 'scan-page-phishing',
            title: 'Scan page for phishing',
            contexts: ['page', 'frame'],
            documentUrlPatterns: ['http://*/*', 'https://*/*']
        });

        chrome.contextMenus.onClicked.addListener((info, tab) => {
            this.handleContextMenuClick(info, tab);
        });
    }

    async handleContextMenuClick(info, tab) {
        if (info.menuItemId === 'scan-page-phishing') {
            try {
                if (!this.geminiApiKey) {
                    chrome.tabs.sendMessage(tab.id, {
                        action: 'showNotification',
                        message: 'Please configure your Gemini API key in the extension popup first',
                        type: 'error'
                    });
                    return;
                }
                if (!this.isScannableUrl(tab.url)) {
                    chrome.tabs.sendMessage(tab.id, {
                        action: 'showNotification',
                        message: 'Cannot scan this type of page',
                        type: 'error'
                    });
                    return;
                }
                await this.scanPage(tab.id, tab.url, 'contextMenu');
            } catch (error) {
                console.error('Error scanning page from context menu:', error);
                chrome.tabs.sendMessage(tab.id, {
                    action: 'showNotification',
                    message: `Scan failed: ${error.message}`,
                    type: 'error'
                });
            }
        }
    }

    async handleMessage(request, sender, sendResponse) {
        try {
            switch (request.action) {
                case 'scanPage':
                    const result = await this.scanPage(request.tabId, request.url, request.scanSource || 'popup');
                    sendResponse({ result });
                    break;
                case 'getPageContent':
                    const content = await this.getPageContent(request.tabId);
                    sendResponse({ content });
                    break;
                default:
                    sendResponse({ error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ error: error.message });
        }
    }

    handleStorageChange(changes, namespace) {
        if (namespace === 'sync') {
            if (changes.geminiApiKey) {
                this.geminiApiKey = changes.geminiApiKey.newValue;
            }
            if (changes.safeThreshold) {
                this.safeThreshold = changes.safeThreshold.newValue;
            }
            if (changes.cautionThreshold) {
                this.cautionThreshold = changes.cautionThreshold.newValue;
            }
            if (changes.selectedModel) {
                this.selectedModel = changes.selectedModel.newValue;
                this.currentModel = GEMINI_CONFIG.models[this.selectedModel];
            }
        }
    }

    handleTabActivated(activeInfo) {
        const tabId = activeInfo.tabId;
        
        if (this.scannedTabs.has(tabId)) {
            const result = this.scannedTabs.get(tabId);
            this.updateBadge(tabId, result);
        } else {
            this.clearBadge(tabId);
        }
    }

    handleTabUpdated(tabId, changeInfo, tab) {
        if (changeInfo.url) {
            this.scannedTabs.delete(tabId);
            this.clearBadge(tabId);
        }
    }

    async scanPage(tabId, url, scanSource = 'popup') {
        try {
            await this.loadSettings();
            this.currentModel = GEMINI_CONFIG.models[this.selectedModel];
            
            if (!this.geminiApiKey) {
                throw new Error('API key not configured');
            }

            if (!this.isScannableUrl(url)) {
                throw new Error('Cannot scan this type of page');
            }

            const pageData = await this.getPageContent(tabId);
            pageData.isDomainSuspicious = this.isSuspiciousDomain(url);
            const result = await this.analyzeWithGemini(pageData);
            
            this.scannedTabs.set(tabId, result);
            this.updateBadge(tabId, result);
            
            if (scanSource === 'contextMenu') {
                await this.saveToHistory(result);
            }
            
            if (scanSource === 'contextMenu') {
                const score = result.legitimacyScore;
                
                if (score < this.cautionThreshold) {
                    await this.sendContentScriptMessage(tabId, 'showPhishingWarning', result);
                } else if (score < this.safeThreshold) {
                    await this.sendContentScriptMessage(tabId, 'showSuspiciousWarning', {
                        ...result,
                        reasoning: [
                            'AI analysis indicates potential phishing risks - please proceed with caution.',
                            ...result.reasoning
                        ]
                    });
                } else {
                    await this.sendContentScriptMessage(tabId, 'showSafeIndicator', result);
                }
            }

            return result;
        } catch (error) {
            console.error('Error scanning page:', error);
            throw error;
        }
    }


    async getPageContent(tabId) {
        try {
            await this.ensureContentScriptInjected(tabId);

            // Execute page data extraction function in page context
            const results = await chrome.scripting.executeScript({
                target: { tabId: tabId },
                func: this.extractPageDataFunction
            });

            if (!results || !results[0] || !results[0].result) {
                return await this.fallbackPageExtraction(tabId);
            }

            return results[0].result;
        } catch (error) {
            console.error('Error getting page content:', error);
            try {
                return await this.fallbackPageExtraction(tabId);
            } catch (fallbackError) {
                console.error('Fallback extraction also failed:', fallbackError);
                throw new Error(`Failed to extract page content: ${error.message}`);
            }
        }
    }


    async ensureContentScriptInjected(tabId) {
        try {
            // Check if content script is already injected by testing for a specific global variable
            const results = await chrome.scripting.executeScript({
                target: { tabId: tabId },
                func: () => window.phishGuardContentLoaded
            });

            // If content script is not loaded, inject it
            if (!results || !results[0] || !results[0].result) {
                await chrome.scripting.executeScript({
                    target: { tabId: tabId },
                    files: ['src/content.js']
                });
            }
        } catch (error) {
            console.error('Error injecting content script:', error);  
        }
    }


    async fallbackPageExtraction(tabId) {
        try {
            // Execute minimal extraction function in page context
            const results = await chrome.scripting.executeScript({
                target: { tabId: tabId },
                func: () => {
                    try {
                        // Extract basic page information without complex analysis
                        const title = document.title || '';
                        const bodyText = document.body ? document.body.innerText.substring(0, 2000) : '';
                        const metaDescription = document.querySelector('meta[name="description"]');
                        const description = metaDescription ? metaDescription.content : '';

                        return {
                            title,
                            description,
                            bodyText,
                            suspiciousElements: {
                                iframes: document.querySelectorAll('iframe').length,
                                externalLinks: 0,
                                formInputs: document.querySelectorAll('input[type="password"], input[type="email"]').length,
                                httpsStatus: window.location.protocol === 'https:',
                                hasLoginForm: document.querySelectorAll('form').length > 0
                            },
                            urlInfo: {
                                protocol: window.location.protocol,
                                hostname: window.location.hostname,
                                pathname: window.location.pathname,
                                fullUrl: window.location.href
                            },
                            timestamp: Date.now(),
                            extractionMethod: 'fallback'
                        };
                    } catch (e) {
                        // Return minimal error state if even fallback extraction fails
                        return {
                            title: 'Extraction Error',
                            description: '',
                            bodyText: '',
                            suspiciousElements: {
                                iframes: 0,
                                externalLinks: 0,
                                formInputs: 0,
                                httpsStatus: false,
                                hasLoginForm: false
                            },
                            urlInfo: {
                                protocol: 'unknown',
                                hostname: 'unknown',
                                pathname: 'unknown',
                                fullUrl: 'unknown'
                            },
                            timestamp: Date.now(),
                            error: e.message,
                            extractionMethod: 'fallback-error'
                        };
                    }
                }
            });

            if (results && results[0] && results[0].result) {
                return results[0].result;
            }

            // Final fallback using only tab information if script execution fails
            const tab = await chrome.tabs.get(tabId);
            return {
                title: tab.title || 'Unknown',
                description: '',
                bodyText: 'Content extraction failed',
                suspiciousElements: {
                    iframes: 0,
                    externalLinks: 0,
                    formInputs: 0,
                    httpsStatus: tab.url.startsWith('https:'),
                    hasLoginForm: false
                },
                urlInfo: {
                    protocol: new URL(tab.url).protocol,
                    hostname: new URL(tab.url).hostname,
                    pathname: new URL(tab.url).pathname,
                    fullUrl: tab.url
                },
                timestamp: Date.now(),
                extractionMethod: 'minimal-tab-info'
            };

        } catch (error) {
            throw new Error(`All extraction methods failed: ${error.message}`);
        }
    }


    extractPageDataFunction() {
        try {
            const title = document.title || '';
            const bodyText = document.body ? document.body.innerText.substring(0, 5000) : '';
            const metaDescription = document.querySelector('meta[name="description"]');
            const description = metaDescription ? metaDescription.content : '';

            const suspiciousElements = {
                iframes: document.querySelectorAll('iframe').length,
                externalLinks: Array.from(document.querySelectorAll('a[href]'))
                    .filter(a => {
                        try {
                            const linkHost = new URL(a.href).hostname;
                            return linkHost !== window.location.hostname;
                        } catch {
                            return false;
                        }
                    }).length,
                formInputs: document.querySelectorAll('input[type="password"], input[type="email"]').length,
                httpsStatus: window.location.protocol === 'https:',
                hasLoginForm: document.querySelectorAll('form').length > 0
            };

            const urlInfo = {
                protocol: window.location.protocol,
                hostname: window.location.hostname,
                pathname: window.location.pathname,
                fullUrl: window.location.href
            };

            return {
                title,
                description,
                bodyText,
                suspiciousElements,
                urlInfo,
                timestamp: Date.now(),
                extractionMethod: 'primary'
            };

        } catch (error) {
            console.error('Error extracting page data:', error);
            return {
                title: document.title || '',
                description: '',
                bodyText: '',
                suspiciousElements: {},
                urlInfo: { fullUrl: window.location.href },
                error: error.message,
                extractionMethod: 'primary-error'
            };
        }
    }


    async analyzeWithGemini(pageData) {
        const prompt = this.buildAnalysisPrompt(pageData);
        
        try {
            // Make API request to current Gemini model
            const response = await fetch(`${GEMINI_CONFIG.apiSettings.baseUrl}/models/${this.currentModel}:generateContent?key=${this.geminiApiKey}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: {
                        temperature: GEMINI_CONFIG.apiSettings.temperature,
                        maxOutputTokens: GEMINI_CONFIG.apiSettings.maxOutputTokens
                    }
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`API request failed: ${errorData.error?.message || response.statusText}`);
            }

            const data = await response.json();
            const generatedText = data.candidates?.[0]?.content?.parts?.[0]?.text;

            if (!generatedText) {
                throw new Error('No response from Gemini API');
            }

            return this.parseGeminiResponse(generatedText, pageData.urlInfo.fullUrl);

        } catch (error) {
            console.error('Gemini analysis failed:', error);
            
            // Try next model in fallback chain (expensive to cheap)
            const nextModel = this.getNextFallbackModel();
            if (nextModel) {
                const currentModelName = this.getModelDisplayName(this.currentModel);
                const nextModelName = this.getModelDisplayName(nextModel);
                
                // Notify user about fallback
                this.showFallbackNotification(currentModelName, nextModelName);
                
                this.currentModel = nextModel;
                return this.analyzeWithGemini(pageData);
            } else {
                // Reset to user's selected model for next scan
                this.currentModel = GEMINI_CONFIG.models[this.selectedModel];
                throw new Error(`All Gemini models failed: ${error.message}`);
            }
        }
    }


    getNextFallbackModel() {
        // Find current model in the fallback order
        const currentModelKey = Object.keys(GEMINI_CONFIG.models).find(
            key => GEMINI_CONFIG.models[key] === this.currentModel
        );
        
        if (!currentModelKey) {
            return null;
        }
        
        const currentIndex = GEMINI_CONFIG.fallbackOrder.indexOf(currentModelKey);
        const nextIndex = currentIndex + 1;
        
        if (nextIndex < GEMINI_CONFIG.fallbackOrder.length) {
            const nextModelKey = GEMINI_CONFIG.fallbackOrder[nextIndex];
            return GEMINI_CONFIG.models[nextModelKey];
        }
        
        return null;
    }


    getModelDisplayName(modelValue) {
        const displayNames = {
            'gemini-2.5-pro': 'Gemini 2.5 Pro',
            'gemini-2.5-flash': 'Gemini 2.5 Flash',
            'gemini-2.5-flash-lite': 'Gemini 2.5 Flash Lite'
        };
        
        return displayNames[modelValue] || modelValue;
    }


    async showFallbackNotification(currentModelName, nextModelName) {
        try {
            // Get current active tab
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tabs.length > 0) {
                const tabId = tabs[0].id;
                
                // Send notification to content script
                await chrome.tabs.sendMessage(tabId, {
                    action: 'showNotification',
                    message: `${currentModelName} failed. Switching to ${nextModelName}...`,
                    type: 'warning'
                });
            }
        } catch (error) {
            console.warn('Failed to show fallback notification:', error);
        }
    }

buildAnalysisPrompt(pageData) {
    return `You are an expert cybersecurity analyst specializing in phishing detection.
    Score how legitimate the webpage is (0-100) based on the data provided.

    Respond with ONLY this JSON:
    {
        "legitimacyScore": number,
        "reasoning": ["Reason 1", "Reason 2", "Reason 3"] // max 3 reasons, concisely explain in simple terms
    }

    SCORING RUBRIC (do not reveal):
    0-39: likely phishing/malicious
    40-59: suspicious, proceed with caution
    60-79: mostly legitimate (minor concerns)
    80-100: highly legitimate

    WEBPAGE DATA
    - URL: ${pageData.urlInfo.fullUrl}
    - Protocol: ${pageData.urlInfo.protocol}
    - Domain: ${pageData.urlInfo.hostname}
    - Title: ${pageData.title}
    - Meta Description: ${pageData.description}

    CONTENT ANALYSIS
    - Body Text (first 1000 chars): ${pageData.bodyText.substring(0, 1000)}
    - External Links: ${pageData.suspiciousElements.externalLinks || 0}
    - iFrames: ${pageData.suspiciousElements.iframes || 0}
    - Password/Email Fields: ${pageData.suspiciousElements.formInputs || 0}
    - HTTPS Enabled: ${pageData.suspiciousElements.httpsStatus || false}
    - Has Login Form: ${pageData.suspiciousElements.hasLoginForm || false}
    - Domain Contains Suspicious Keywords: ${pageData.isDomainSuspicious || false}

    Analysis tips (internal, do not reveal): Weigh URL trust signals, domain age, HTTPS, forms, content-title consistency, and common phishing patterns. If data is incomplete, state uncertainty in reasoning.`;
    }



    parseGeminiResponse(responseText, url) {
        try {
            const cleanedResponse = responseText.replace(/```json|```/g, '').trim();
            
            let jsonMatch = cleanedResponse.match(/\{[\s\S]*\}/);
            if (!jsonMatch) {
                return this.fallbackAnalysis(url, responseText);
            }

            const parsed = JSON.parse(jsonMatch[0]);
            
            const legitimacyScore = Math.min(Math.max(parsed.legitimacyScore || 50, 0), 100);
            
            return {
                legitimacyScore,
                reasoning: Array.isArray(parsed.reasoning) ? parsed.reasoning : ['Analysis completed'],
                url: url,
                timestamp: Date.now(),
                modelUsed: this.currentModel,
                modelDisplayName: this.getModelDisplayName(this.currentModel)
            };
        } catch (error) {
            console.error('Error parsing Gemini response:', error);
            return this.fallbackAnalysis(url, responseText);
        }
    }


    fallbackAnalysis(url, responseText) {
        const lowerResponse = responseText.toLowerCase();
        let legitimacyScore = 50;
        let reasoning = ['Automated analysis based on response patterns'];

        if (lowerResponse.includes('phishing') || lowerResponse.includes('suspicious') || lowerResponse.includes('malicious')) {
            legitimacyScore = 25;
            reasoning = ['Phishing indicators detected in content analysis'];
        } else if (lowerResponse.includes('legitimate') || lowerResponse.includes('safe') || lowerResponse.includes('trusted')) {
            legitimacyScore = 65;
            reasoning = ['Content appears legitimate based on analysis'];
        }

        return {
            legitimacyScore,
            reasoning,
            url,
            timestamp: Date.now(),
            fallback: true,
            modelUsed: this.currentModel,
            modelDisplayName: this.getModelDisplayName(this.currentModel)
        };
    }


    isSuspiciousDomain(url) {
        try {
            const domain = new URL(url).hostname.toLowerCase();
            return domain.includes('secure') || 
                   domain.includes('verify') || 
                   domain.includes('update') ||
                   domain.includes('account') ||
                   domain.includes('login') ||
                   domain.includes('signin');
        } catch {
            return false;
        }
    }


    isScannableUrl(url) {
        if (!url || typeof url !== 'string') return false;

        const unscannable = [
            'chrome://', 'chrome-extension://',
            'about:', 'file://', 'data:', 'javascript:', 'mailto:',
            'tel:', 'ftp://', 'chrome-search://', 'chrome-devtools://'
        ];

        const urlLower = url.toLowerCase();
        return !unscannable.some(scheme => urlLower.startsWith(scheme));
    }


    async sendContentScriptMessage(tabId, action, result) {
        try {
            await chrome.tabs.sendMessage(tabId, {
                action: action,
                result: result
            });
        } catch (error) {
            console.warn(`Failed to send message to tab ${tabId}:`, error.message);
        }
    }



    updateBadge(tabId, result) {
        const score = result.legitimacyScore;

        let badgeText = '';
        let badgeColor = '';

        if (score >= this.safeThreshold) {
            badgeText = '✔️';
            badgeColor = '#10b981';
        } else if (score >= this.cautionThreshold) {
            badgeText = '❔';
            badgeColor = '#f59e0b';
        } else {
            badgeText = '❕';
            badgeColor = '#dc2626';
        }

        chrome.action.setBadgeText({ tabId: tabId, text: badgeText });
        chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: badgeColor });
    }

    clearBadge(tabId) {
        chrome.action.setBadgeText({ tabId: tabId, text: '' });
        chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#00000000' });
    }

    async saveToHistory(result) {
        try {
            const storage = await chrome.storage.sync.get(['scanHistory']);
            let scanHistory = storage.scanHistory || [];

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

            scanHistory.unshift(historyItem);
            scanHistory = scanHistory.slice(0, 10);

            await chrome.storage.sync.set({ scanHistory: scanHistory });
        } catch (error) {
            console.error('Error saving scan to history:', error);
        }
    }
}

// Initialize the background service worker when script loads
new PhishGuardBackground();
