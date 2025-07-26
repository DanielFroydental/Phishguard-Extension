# PhishGuard AI – Chrome Extension

A Chrome extension leveraging **Google Gemini AI** to detect phishing websites in real time and protect users during browsing.

## Features
- **AI-Powered Detection:** Analyzes webpages using Google Gemini.
- **Manual Scanning:** Trigger scans via popup or right-click context menu.
- **Visual Alerts:** Color-coded banners for quick risk assessment.
- **Scan History:** Review recent scan results.

## Requirements
- Google Chrome (Manifest V3 compatible)
- [Google Gemini API Key](https://makersuite.google.com/app/apikey)

## Installation
1. Clone or download the extension folder.
2. Open `chrome://extensions/` in Chrome.
3. Enable **Developer Mode**.
4. Click **Load unpacked** and select the folder.
5. Enter your Gemini API key in the popup **Settings**.

## Usage
- **Manual Scan:** Click the extension icon and choose **Analyze Page**.
- **Context Menu:** Right-click the page and select **Scan page for phishing**.
- **Results:** A banner or a popup UI update displays the verdict, confidence score and reasoning.

## Technical Overview
- **background.js:** Core logic, API requests, and context menu handling.
- **content.js:** Injected into pages; collects data and renders banners.
- **popup.js / popup.html:** User interface, API key management, and scan history.
