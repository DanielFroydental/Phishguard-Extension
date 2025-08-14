# PhishGuard AI – Chrome Extension

A Chrome extension leveraging **Google Gemini AI** to detect phishing websites in real-time with advanced features and intelligent fallback mechanisms.

## Features
- **AI-Powered Detection:** Multi-model support (Pro, Flash, Flash Lite) with intelligent fallback
- **Legitimacy Scoring:** 0-100% score with detailed reasoning and color-coded results
- **Smart UI:** Real-time badge updates, context menu integration, and auto-hide banners
- **Customizable Protection:** Adjustable thresholds (Safe 70-95%, Caution 30-70%) and model selection
- **Advanced Analysis:** Detects suspicious elements, content flags, and phishing patterns
- **Scan History:** Track last 10 scans with detailed results

## Requirements
- Google Chrome (Manifest V3 compatible)
- [Google Gemini API Key](https://makersuite.google.com/app/apikey)

## Installation
1. Clone or download the extension folder
2. Open `chrome://extensions/` in Chrome
3. Enable **Developer Mode**
4. Click **Load unpacked** and select the folder
5. Enter your Gemini API key in the popup **Settings**

## Usage
- **Manual Scan:** Click the extension icon and choose **Analyze Page**
- **Context Menu:** Right-click the page and select **Scan page for phishing**
- **Settings:** Configure thresholds, select AI model, and manage API key
- **Results:** Color-coded banners and popup updates show legitimacy score and reasoning

## Technical Overview
- **background.js:** Core logic, API requests with fallback, badge management, and context menu
- **content.js:** Advanced data extraction, suspicious elements detection, banner management, and page monitoring
- **popup.js/html:** User interface, API validation, threshold configuration, and scan history
