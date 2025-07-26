/*
 * Content Script - PhishGuard AI Extension
 * 
 * Manages user-facing warnings and page interactions for the phishing detection system.
 * Injected into webpages to display phishing warnings, extract page content, and handle banner UI.
 * 
 * Key responsibilities:
 * - Display dynamic warning banners for phishing/suspicious/safe sites
 * - Extract detailed page content for AI analysis (text, forms, links, security indicators)
 * - Manage banner animations, auto-hiding, and user interactions
 * - Handle page navigation changes and banner state management
 * - Provide visual feedback to users about website safety status
 */

/**
 * Content script class that handles all webpage interactions and warning displays.
 * Coordinates with background service worker to show appropriate security warnings.
 */
class PhishGuardContent {
    constructor() {
        this.currentBanner = null; // Currently displayed banner element
        this.pageAnalyzed = false; // Flag to track if current page was analyzed
        this.init();
    }

    init() {
        // Listen for messages from background service worker
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true;
        });
        this.observePageChanges();
    }

    /**
     * Handle messages from background service worker.
     * Routes different action types to appropriate banner display methods.
     */
    handleMessage(request, sender, sendResponse) {
        switch (request.action) {
            case 'showPhishingWarning':
                this.showPhishingWarning(request.result);
                sendResponse({ success: true });
                break;
            case 'showSuspiciousWarning':
                this.showSuspiciousWarning(request.result);
                sendResponse({ success: true });
                break;
            case 'showSafeIndicator':
                this.showSafeIndicator(request.result);
                sendResponse({ success: true });
                break;
            case 'showNotification':
                this.showNotification(request.message, request.type);
                sendResponse({ success: true });
                break;
            default:
                sendResponse({ error: 'Unknown action' });
        }
    }

    /**
     * Display prominent phishing warning banner at top of page.
     * Creates highly visible red banner with warning information and user actions.
     */
    showPhishingWarning(result) {
        this.removeBanner();

        const banner = document.createElement('div');
        banner.id = 'phishguard-warning';
        banner.className = 'phishguard-banner warning';
        banner.setAttribute('dir', 'ltr');
        banner.style.cssText = 'position: fixed !important; top: 0 !important; bottom: auto !important; left: 0 !important; right: 0 !important; z-index: 2147483647 !important; direction: ltr !important; text-align: left !important; unicode-bidi: embed !important;';
        banner.style.setProperty('position', 'fixed', 'important');
        banner.style.setProperty('top', '0', 'important');
        banner.style.setProperty('bottom', 'auto', 'important');
        banner.style.setProperty('left', '0', 'important');
        banner.style.setProperty('right', '0', 'important');
        banner.style.setProperty('z-index', '2147483647', 'important');
        
        banner.innerHTML = `
            <div class="phishing-banner-content" dir="ltr" style="direction: ltr !important; text-align: left !important;">
                <div class="phishing-banner-header" dir="ltr" style="direction: ltr !important; display: flex !important; flex-direction: row !important;">
                    <div class="phishing-banner-icon" style="order: 1 !important;">!</div>
                    <div class="phishing-banner-title" style="order: 2 !important; text-align: left !important;">
                        <strong>PHISHING WEBSITE DETECTED</strong>
                        <div class="phishing-banner-subtitle">
                            This website may be trying to steal your personal information
                        </div>
                    </div>
                    <button class="phishing-banner-close" style="order: 3 !important;" onclick="this.closest('.phishguard-banner').remove()">X</button>
                </div>
                
                <div class="phishing-banner-details">
                    <div class="phishing-confidence">
                        Phishing Risk Level: <strong>${Math.round(result.confidence)}%</strong>
                    </div>
                    <div class="phishing-reasons">
                        <strong>Warning signs detected:</strong>
                        <ul>
                            ${(result.reasoning || result.reasons || []).map(reason => `<li>${reason}</li>`).join('')}
                        </ul>
                    </div>
                </div>
                
                <div class="phishing-banner-actions" style="direction: ltr !important; display: flex !important; flex-direction: row !important;">
                    <button class="phishing-action-btn danger" onclick="window.history.back()">← Go Back</button>
                    <button class="phishing-action-btn secondary" onclick="this.closest('.phishguard-banner').remove()">Continue Anyway</button>
                </div>
            </div>
        `;

        document.body.appendChild(banner);
        this.currentBanner = banner;

        setTimeout(() => {
            banner.classList.add('show');
            banner.style.setProperty('position', 'fixed', 'important');
            banner.style.setProperty('z-index', '2147483647', 'important');
        }, 10);

        // Auto-hide after 15 seconds
        setTimeout(() => {
            if (banner.parentNode && !banner.classList.contains('user-interacted')) {
                banner.classList.add('auto-hiding');
                setTimeout(() => {
                    if (banner.parentNode) banner.remove();
                }, 500);
            }
        }, 15000);

        banner.addEventListener('mouseenter', () => banner.classList.add('user-interacted'));
    }

    /**
     * Display orange warning banner for suspicious but uncertain content.
     * Used for legitimate sites with low confidence or sites with suspicious elements.
     */
    showSuspiciousWarning(result) {
        this.removeBanner();

        const banner = document.createElement('div');
        banner.id = 'phishguard-suspicious';
        banner.className = 'phishguard-banner suspicious';
        banner.setAttribute('dir', 'ltr');
        banner.style.cssText = 'position: fixed !important; top: 0 !important; bottom: auto !important; left: 0 !important; right: 0 !important; z-index: 2147483647 !important; direction: ltr !important; text-align: left !important; unicode-bidi: embed !important;';
        banner.style.setProperty('position', 'fixed', 'important');
        banner.style.setProperty('top', '0', 'important');
        banner.style.setProperty('bottom', 'auto', 'important');
        banner.style.setProperty('left', '0', 'important');
        banner.style.setProperty('right', '0', 'important');
        banner.style.setProperty('z-index', '2147483647', 'important');
        
        banner.innerHTML = `
            <div class="phishing-banner-content" dir="ltr" style="direction: ltr !important; text-align: left !important;">
                <div class="phishing-banner-header" dir="ltr" style="direction: ltr !important; display: flex !important; flex-direction: row !important;">
                    <div class="phishing-banner-icon" style="order: 1 !important;">⚠</div>
                    <div class="phishing-banner-title" style="order: 2 !important; text-align: left !important;">
                        <strong>Suspicious Website Detected</strong>
                        <div class="phishing-banner-subtitle">
                            Exercise caution - this website appears legitimate but has some suspicious elements
                        </div>
                    </div>
                    <button class="phishing-banner-close" style="order: 3 !important;" onclick="this.closest('.phishguard-banner').remove()">
                        X
                    </button>
                </div>
                
                <div class="phishing-banner-details">
                    <div class="phishing-confidence">
                        Confidence in Legitimacy: <strong>${Math.round(result.confidence)}%</strong>
                    </div>
                    <div class="phishing-reasons">
                        <strong>Caution reasons:</strong>
                        <ul>
                            ${(result.reasoning || result.reasons || []).map(reason => `<li>${reason}</li>`).join('')}
                        </ul>
                    </div>
                </div>
                
                <div class="phishing-banner-actions" style="direction: ltr !important; display: flex !important; flex-direction: row !important;">
                    <button class="phishing-action-btn warning" onclick="window.history.back()">
                        ← Go Back
                    </button>
                    <button class="phishing-action-btn secondary" onclick="this.closest('.phishguard-banner').remove()">
                        Continue with Caution
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(banner);
        this.currentBanner = banner;

        // Animate in
        setTimeout(() => {
            banner.classList.add('show');
            banner.style.setProperty('position', 'fixed', 'important');
            banner.style.setProperty('z-index', '2147483647', 'important');
        }, 10);

        // Auto-hide after 10 seconds
        setTimeout(() => {
            if (banner.parentNode && !banner.classList.contains('user-interacted')) {
                banner.classList.add('auto-hiding');
                setTimeout(() => {
                    if (banner.parentNode) {
                        banner.remove();
                    }
                }, 500);
            }
        }, 10000);

        banner.addEventListener('mouseenter', () => {
            banner.classList.add('user-interacted');
        });
    }

    /**
     * Display green confirmation banner for legitimate websites.
     * Shows positive feedback when site is determined to be safe.
     */
    showSafeIndicator(result) {
        this.removeBanner();

        const banner = document.createElement('div');
        banner.id = 'phishguard-safe';
        banner.className = 'phishguard-banner safe';
        banner.setAttribute('dir', 'ltr');
        banner.style.cssText = 'position: fixed !important; top: 0 !important; bottom: auto !important; left: 0 !important; right: 0 !important; z-index: 2147483647 !important; direction: ltr !important; text-align: left !important; unicode-bidi: embed !important;';
        banner.style.setProperty('position', 'fixed', 'important');
        banner.style.setProperty('top', '0', 'important');
        banner.style.setProperty('bottom', 'auto', 'important');
        banner.style.setProperty('left', '0', 'important');
        banner.style.setProperty('right', '0', 'important');
        banner.style.setProperty('z-index', '2147483647', 'important');
        
        const domain = window.location.hostname;
        const isSecure = window.location.protocol === 'https:';
        
        banner.innerHTML = `
            <div class="phishing-banner-content safe-content" dir="ltr" style="direction: ltr !important; text-align: left !important;">
                <div class="phishing-banner-header" dir="ltr" style="direction: ltr !important; display: flex !important; flex-direction: row !important;">
                    <div class="phishing-banner-icon" style="order: 1 !important;"></div>
                    <div class="phishing-banner-title" style="order: 2 !important; text-align: left !important;">
                        <strong>Website appears legitimate</strong>
                        <div class="phishing-banner-subtitle">
                            Scanned by PhishGuard AI <span class="confidence-pill">${Math.round(result.confidence)}% confidence</span>
                        </div>
                        <div class="site-info" style="margin-top: 4px; font-size: 12px; opacity: 0.85; display: flex; align-items: center; gap: 5px;">
                            <span style="color: ${isSecure ? '#a7f3d0' : '#fcd34d'};">${isSecure ? '🔒 Secure' : '⚠️ Not Secure'}</span>
                            <span style="margin: 0 4px;">•</span>
                            <span style="font-weight: 600; overflow: hidden; text-overflow: ellipsis; max-width: 250px; white-space: nowrap;">${domain}</span>
                        </div>
                    </div>
                    <button class="phishing-banner-close" style="order: 3 !important;" id="safe-banner-close">
                        X
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(banner);
        this.currentBanner = banner;

        // Add click event listener for the close button
        const closeButton = banner.querySelector('#safe-banner-close');
        closeButton.addEventListener('click', () => {
            banner.classList.add('auto-hiding');
            setTimeout(() => {
                if (banner.parentNode) {
                    banner.remove();
                }
            }, 300);
        });

        // Animate in
        setTimeout(() => {
            banner.classList.add('show');
            banner.style.setProperty('position', 'fixed', 'important');
            banner.style.setProperty('z-index', '2147483647', 'important');
        }, 10);
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            if (banner.parentNode && !banner.classList.contains('user-interacted')) {
                banner.classList.add('auto-hiding');
                setTimeout(() => {
                    if (banner.parentNode) {
                        banner.remove();
                    }
                }, 400);
            }
        }, 5000);
    }

    removeBanner() {
        if (this.currentBanner && this.currentBanner.parentNode) {
            this.currentBanner.remove();
            this.currentBanner = null;
        }
        // Remove any existing banners to prevent duplicates
        const existingWarning = document.getElementById('phishguard-warning');
        const existingSafe = document.getElementById('phishguard-safe');
        const existingSuspicious = document.getElementById('phishguard-suspicious');
        
        if (existingWarning) existingWarning.remove();
        if (existingSafe) existingSafe.remove();
        if (existingSuspicious) existingSuspicious.remove();
    }

    /**
     * Extract comprehensive page data for AI analysis.
     * Gathers text content, metadata, forms, links, and security indicators.
     */
    extractPageData() {
        try {
            const title = document.title || '';
            const bodyText = document.body ? 
                document.body.innerText.substring(0, 3000) : '';
            const metaDescription = document.querySelector('meta[name="description"]');
            const description = metaDescription ? metaDescription.content : '';
            const lang = document.documentElement.lang || 
                        document.querySelector('meta[http-equiv="content-language"]')?.content || '';

            const suspiciousElements = {
                iframes: document.querySelectorAll('iframe').length,
                externalLinks: this.countExternalLinks(),
                formInputs: document.querySelectorAll('input[type="password"], input[type="email"]').length,
                httpsStatus: window.location.protocol === 'https:',
                hasLoginForm: this.hasLoginForm(),
                popups: document.querySelectorAll('[onclick*="popup"], [onclick*="window.open"]').length,
                redirects: this.checkForRedirects(),
                hiddenElements: document.querySelectorAll('[style*="display:none"], [style*="visibility:hidden"]').length
            };

            const forms = Array.from(document.querySelectorAll('form')).map(form => ({
                action: form.action || '',
                method: form.method || 'get',
                inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                    type: input.type,
                    name: input.name,
                    required: input.required
                }))
            }));

            const urlInfo = {
                protocol: window.location.protocol,
                hostname: window.location.hostname,
                pathname: window.location.pathname,
                search: window.location.search,
                fullUrl: window.location.href,
                port: window.location.port
            };

            const contentFlags = this.analyzeContentFlags(bodyText, title);

            return {
                title,
                description,
                bodyText,
                language: lang,
                suspiciousElements,
                forms,
                urlInfo,
                contentFlags,
                timestamp: Date.now(),
                userAgent: navigator.userAgent
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
                timestamp: Date.now()
            };
        }
    }

    /**
     * Count external links on the page.
     */
    countExternalLinks() {
        return Array.from(document.querySelectorAll('a[href]'))
            .filter(a => {
                try {
                    const linkHost = new URL(a.href).hostname;
                    return linkHost !== window.location.hostname;
                } catch {
                    return false;
                }
            }).length;
    }

    /**
     * Check if the page contains a login form.
     * Looks for forms with password and email/username fields.
    */
    hasLoginForm() {
        const forms = document.querySelectorAll('form');
        for (const form of forms) {
            const hasPassword = form.querySelector('input[type="password"]');
            const hasEmail = form.querySelector('input[type="email"]');
            const hasUsernameField = form.querySelector('input[name*="user"], input[name*="login"], input[name*="email"]');
            
            if (hasPassword && (hasEmail || hasUsernameField)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check for meta refresh tags and JavaScript redirects.
     */
    checkForRedirects() {
        const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
        const jsRedirects = document.body ? 
            document.body.innerHTML.match(/(window\.location|location\.href|location\.replace)/gi) || [] : [];
        
        return {
            metaRefresh: !!metaRefresh,
            jsRedirects: jsRedirects.length,
            refreshContent: metaRefresh ? metaRefresh.content : null
        };
    }

    /**
     * Analyze page content for common phishing indicators.
     * Looks for urgency, scam phrases, threats, excessive capitalization, and spelling errors.
     */
    analyzeContentFlags(bodyText, title) {
        const text = (bodyText + ' ' + title).toLowerCase();
        
        const urgencyWords = [
            'urgent', 'immediate', 'expire', 'suspend', 'verify', 'confirm',
            'update', 'secure', 'alert', 'warning', 'limited time', 'act now'
        ];

        const scamPhrases = [
            'click here', 'verify account', 'confirm identity', 'update payment',
            'suspended account', 'unusual activity', 'security alert',
            'winner', 'congratulations', 'prize', 'lottery'
        ];

        const threats = [
            'close account', 'legal action', 'penalty', 'fine',
            'restricted', 'locked', 'blocked'
        ];

        return {
            urgencyScore: urgencyWords.filter(word => text.includes(word)).length,
            scamScore: scamPhrases.filter(phrase => text.includes(phrase)).length,
            threatScore: threats.filter(threat => text.includes(threat)).length,
            hasExcessiveCaps: (text.match(/[A-Z]/g) || []).length > text.length * 0.1,
            hasExcessiveExclamation: (text.match(/!/g) || []).length > 5,
            hasSpellingErrors: this.detectSpellingErrors(text)
        };
    }

    /**
     * Detect common spelling errors in the page text.
     * Uses a predefined list of common misspellings.
     */
    detectSpellingErrors(text) {
        const commonMisspellings = [
            'amazom', 'gogle', 'microsooft', 'facbook',
            'bankk', 'securee', 'varify', 'acount', 'recieve'
        ];

        return commonMisspellings.some(error => text.includes(error));
    }

    /**
     * Observe page changes (e.g., navigation, content updates).
     * Resets banner state and sends URL change messages to background script.
     */
    observePageChanges() {
        let lastUrl = location.href;
        
        new MutationObserver(() => {
            const url = location.href;
            if (url !== lastUrl) {
                lastUrl = url;
                this.pageAnalyzed = false;
                this.removeBanner();
                
                chrome.runtime.sendMessage({
                    action: 'urlChanged',
                    url: url
                });
            }
        }).observe(document, { subtree: true, childList: true });
    }

    /**
     * Show a notification message to the user.
     *  Displays a temporary message in the corner of the screen.
     */
    showNotification(message, type = 'info') {
        const existingNotification = document.querySelector('.phishguard-notification');
        if (existingNotification) {
            existingNotification.remove();
        }

        const notification = document.createElement('div');
        notification.className = 'phishguard-notification';
        notification.style.cssText = `
            position: fixed !important;
            top: 20px !important;
            right: 20px !important;
            z-index: 2147483647 !important;
            background: ${type === 'error' ? '#f44336' : '#4CAF50'} !important;
            color: white !important;
            padding: 12px 16px !important;
            border-radius: 8px !important;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
            font-size: 14px !important;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15) !important;
            max-width: 300px !important;
            transform: translateX(100%) !important;
            transition: transform 0.3s ease-out !important;
        `;
        
        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 16px;">${type === 'error' ? '!' : 'ℹ'}</span>
                <span>${message}</span>
                <button onclick="this.closest('.phishguard-notification').remove()" 
                        style="margin-left: auto; background: none; border: none; color: white; cursor: pointer; font-size: 18px; padding: 0;">✕</button>
            </div>
        `;

        document.body.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);

        // Auto-hide after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.remove();
                    }
                }, 300);
            }
        }, 5000);
    }
}

// Initialize content script when DOM is ready or already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new PhishGuardContent();
    });
} else {
    new PhishGuardContent();
}
