/**
 * UI Controller - Main application controller managing user interface interactions
 * Coordinates between Storage Module and Sanitizer Engine
 */

class UIController {
  constructor() {
    this.elements = {};
    this.state = {
      currentDetections: [],
      isProcessing: false,
      realTimeEnabled: true,
      deterministicEnabled: true,
      debounceTimer: null
    };
    
    // Debounce delay for real-time processing
    this.debounceDelay = 300;
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.initialize());
    } else {
      this.initialize();
    }
  }

  /**
   * Initialize the application
   */
  initialize() {
    try {
      this.cacheElements();
      this.loadSettings();
      this.loadCurrentProfile();
      this.setupEventListeners();
      this.updateUI();
      this.showWelcomeMessage();
      
      console.log('Data Sanitizer initialized successfully');
    } catch (error) {
      console.error('Failed to initialize application:', error);
      this.showNotification('Failed to initialize application. Please refresh the page.', 'error');
    }
  }

  /**
   * Cache DOM elements for performance
   */
  cacheElements() {
    this.elements = {
      // Input/Output
      inputText: document.getElementById('input-text'),
      outputText: document.getElementById('output-text'),
      
      // Controls
      realTimeToggle: document.getElementById('real-time-toggle'),
      deterministicToggle: document.getElementById('deterministic-toggle'),
      detectBtn: document.getElementById('detect-btn'),
      sanitizeBtn: document.getElementById('sanitize-btn'),
      clearBtn: document.getElementById('clear-btn'),
      
      // Panels
      detectionsList: document.getElementById('detections-list'),
      detectionCounter: document.getElementById('detection-counter'),
      inputCounter: document.getElementById('input-counter'),
      
      // Header controls
      profileSelect: document.getElementById('profile-select'),
      themeSelect: document.getElementById('theme-select'),
      
      // Action buttons
      pasteBtn: document.getElementById('paste-btn'),
      copyBtn: document.getElementById('copy-btn'),
      exportBtn: document.getElementById('export-btn'),
      selectAllBtn: document.getElementById('select-all-btn'),
      selectNoneBtn: document.getElementById('select-none-btn'),
      
      // Status bar
      processingStatus: document.getElementById('processing-status'),
      storageUsage: document.getElementById('storage-usage'),
      
      // Modal
      modalOverlay: document.getElementById('modal-overlay'),
      modal: document.getElementById('modal'),
      modalTitle: document.getElementById('modal-title'),
      modalContent: document.getElementById('modal-content'),
      modalClose: document.getElementById('modal-close'),
      modalCancel: document.getElementById('modal-cancel'),
      modalConfirm: document.getElementById('modal-confirm'),
      
      // Privacy warning
      privacyWarning: document.getElementById('privacy-warning'),
      closeWarning: document.getElementById('close-warning'),
      
      // Management buttons
      manageProfilesBtn: document.getElementById('manage-profiles-btn'),
      manageRulesBtn: document.getElementById('manage-rules-btn'),
      viewHistoryBtn: document.getElementById('view-history-btn'),
      settingsBtn: document.getElementById('settings-btn')
    };
  }

  /**
   * Load application settings
   */
  loadSettings() {
    const settings = window.storage.getSettings();
    
    // Apply theme
    this.applyTheme(settings.theme);
    this.elements.themeSelect.value = settings.theme;
    
    // Apply processing settings
    this.state.realTimeEnabled = settings.realTimeProcessing;
    this.state.deterministicEnabled = settings.deterministicReplacement;
    this.debounceDelay = settings.debounceDelay;
    
    this.elements.realTimeToggle.checked = settings.realTimeProcessing;
    this.elements.deterministicToggle.checked = settings.deterministicReplacement;
    
    // Show/hide privacy warning
    if (!settings.showWarnings) {
      this.elements.privacyWarning.style.display = 'none';
    }
  }

  /**
   * Load current profile
   */
  loadCurrentProfile() {
    const currentProfileName = window.storage.getCurrentProfile();
    const profiles = window.storage.getProfiles();
    
    // Populate profile dropdown
    this.elements.profileSelect.innerHTML = '';
    Object.keys(profiles).forEach(name => {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = profiles[name].name;
      if (name === currentProfileName) {
        option.selected = true;
      }
      this.elements.profileSelect.appendChild(option);
    });
    
    // Load profile rules and settings
    const profileData = window.storage.loadProfile(currentProfileName);
    if (profileData) {
      this.currentRules = profileData.rules;
    } else {
      this.currentRules = window.storage.getRules();
    }
  }

  /**
   * Setup event listeners
   */
  setupEventListeners() {
    // Input text changes
    this.elements.inputText.addEventListener('input', (e) => {
      this.handleInputChange(e.target.value);
    });
    
    // Control toggles
    this.elements.realTimeToggle.addEventListener('change', (e) => {
      this.state.realTimeEnabled = e.target.checked;
      this.saveCurrentSettings();
      if (e.target.checked && this.elements.inputText.value) {
        this.handleInputChange(this.elements.inputText.value);
      }
    });
    
    this.elements.deterministicToggle.addEventListener('change', (e) => {
      this.state.deterministicEnabled = e.target.checked;
      this.saveCurrentSettings();
    });
    
    // Action buttons
    this.elements.detectBtn.addEventListener('click', () => {
      this.performDetection(this.elements.inputText.value);
    });
    
    this.elements.sanitizeBtn.addEventListener('click', () => {
      this.performSanitization(this.elements.inputText.value);
    });
    
    this.elements.clearBtn.addEventListener('click', () => {
      this.clearAll();
    });
    
    // Paste button
    this.elements.pasteBtn.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        this.elements.inputText.value = text;
        this.handleInputChange(text);
      } catch (error) {
        this.showNotification('Failed to paste from clipboard', 'error');
      }
    });
    
    // Copy button
    this.elements.copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(this.elements.outputText.value);
        this.showNotification('Copied to clipboard', 'success');
      } catch (error) {
        this.showNotification('Failed to copy to clipboard', 'error');
      }
    });
    
    // Export button
    this.elements.exportBtn.addEventListener('click', () => {
      this.exportOutput();
    });
    
    // Detection selection buttons
    this.elements.selectAllBtn.addEventListener('click', () => {
      this.selectAllDetections(true);
    });
    
    this.elements.selectNoneBtn.addEventListener('click', () => {
      this.selectAllDetections(false);
    });
    
    // Profile selection
    this.elements.profileSelect.addEventListener('change', (e) => {
      this.switchProfile(e.target.value);
    });
    
    // Theme selection
    this.elements.themeSelect.addEventListener('change', (e) => {
      this.applyTheme(e.target.value);
      this.saveCurrentSettings();
    });
    
    // Privacy warning close
    this.elements.closeWarning.addEventListener('click', () => {
      this.elements.privacyWarning.style.display = 'none';
      const settings = window.storage.getSettings();
      settings.showWarnings = false;
      window.storage.saveSettings(settings);
    });
    
    // Modal controls
    this.elements.modalClose.addEventListener('click', () => {
      this.hideModal();
    });
    
    this.elements.modalCancel.addEventListener('click', () => {
      this.hideModal();
    });
    
    this.elements.modalOverlay.addEventListener('click', (e) => {
      if (e.target === this.elements.modalOverlay) {
        this.hideModal();
      }
    });
    
    // Management buttons (placeholder for now)
    this.elements.manageProfilesBtn.addEventListener('click', () => {
      this.showNotification('Profile management coming soon', 'info');
    });
    
    this.elements.manageRulesBtn.addEventListener('click', () => {
      this.showNotification('Rule management coming soon', 'info');
    });
    
    this.elements.viewHistoryBtn.addEventListener('click', () => {
      this.showNotification('History view coming soon', 'info');
    });
    
    this.elements.settingsBtn.addEventListener('click', () => {
      this.showNotification('Settings panel coming soon', 'info');
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey || e.metaKey) {
        switch (e.key) {
          case 'Enter':
            e.preventDefault();
            this.performSanitization(this.elements.inputText.value);
            break;
          case 'd':
            e.preventDefault();
            this.performDetection(this.elements.inputText.value);
            break;
        }
      }
    });
  }

  /**
   * Handle input text changes
   * @param {string} text 
   */
  handleInputChange(text) {
    // Update character counter
    this.elements.inputCounter.textContent = `${text.length} characters`;
    
    // Clear previous debounce timer
    if (this.state.debounceTimer) {
      clearTimeout(this.state.debounceTimer);
    }
    
    // Perform real-time processing if enabled
    if (this.state.realTimeEnabled && text.trim()) {
      this.state.debounceTimer = setTimeout(() => {
        this.performDetection(text);
      }, this.debounceDelay);
    } else if (!text.trim()) {
      // Clear detections if input is empty
      this.state.currentDetections = [];
      this.updateDetectionPanel([]);
      this.elements.outputText.value = '';
    }
  }

  /**
   * Perform pattern detection
   * @param {string} text 
   */
  performDetection(text) {
    if (!text || this.state.isProcessing) {
      return;
    }
    
    this.state.isProcessing = true;
    this.updateProcessingStatus('Detecting patterns...');
    
    try {
      const startTime = Date.now();
      
      const detections = window.sanitizer.detect(text, {
        rules: this.currentRules,
        includeContext: true,
        contextLength: 20
      });
      
      const processingTime = Date.now() - startTime;
      
      this.state.currentDetections = detections;
      this.updateDetectionPanel(detections);
      
      this.updateProcessingStatus(`Found ${detections.length} patterns (${processingTime}ms)`);
      
      // Auto-sanitize if real-time mode is enabled
      if (this.state.realTimeEnabled) {
        setTimeout(() => {
          this.performSanitization(text, false);
        }, 100);
      }
      
    } catch (error) {
      console.error('Detection failed:', error);
      this.showNotification('Pattern detection failed', 'error');
      this.updateProcessingStatus('Detection failed');
    } finally {
      this.state.isProcessing = false;
    }
  }

  /**
   * Perform sanitization
   * @param {string} text 
   * @param {boolean} addToHistory 
   */
  performSanitization(text, addToHistory = true) {
    if (!text || this.state.isProcessing) {
      return;
    }
    
    this.state.isProcessing = true;
    this.updateProcessingStatus('Sanitizing...');
    
    try {
      const startTime = Date.now();
      
      // Get selected detections for selective sanitization
      const selectedDetections = this.state.currentDetections
        .filter(d => d.selected)
        .map(d => d.ruleId);
      
      try {
        const sanitizedText = window.sanitizer.sanitize(text, {
          rules: this.currentRules,
          deterministicReplacement: this.state.deterministicEnabled,
          selectedDetections: selectedDetections.length > 0 ? selectedDetections : null
        });
        
        const processingTime = Date.now() - startTime;
        
        this.elements.outputText.value = sanitizedText;
        
        this.updateProcessingStatus(`Sanitized in ${processingTime}ms`);
        
        // Add to history if requested
        if (addToHistory) {
          this.addToHistory(text, sanitizedText);
        }
      } catch (error) {
        console.error('Error during sanitization:', error);
        this.updateProcessingStatus('Error during sanitization');
      }
      
    } catch (error) {
      console.error('Sanitization failed:', error);
      this.showNotification('Sanitization failed', 'error');
      this.updateProcessingStatus('Sanitization failed');
    } finally {
      this.state.isProcessing = false;
    }
  }

  /**
   * Update detection panel
   * @param {Detection[]} detections 
   */
  updateDetectionPanel(detections) {
    this.elements.detectionCounter.textContent = `${detections.length} patterns found`;
    
    if (detections.length === 0) {
      this.elements.detectionsList.innerHTML = `
        <div class="no-detections">
          No sensitive patterns detected. Enter text in the input panel to begin analysis.
        </div>
      `;
      return;
    }
    
    // Group detections by category
    const grouped = detections.reduce((acc, detection) => {
      if (!acc[detection.category]) {
        acc[detection.category] = [];
      }
      acc[detection.category].push(detection);
      return acc;
    }, {});
    
    let html = '';
    Object.entries(grouped).forEach(([category, categoryDetections]) => {
      html += `<div class="detection-category-header">${category.toUpperCase()}</div>`;
      
      categoryDetections.forEach((detection, index) => {
        html += `
          <div class="detection-item ${detection.selected ? 'selected' : ''}" 
               data-detection-id="${detection.ruleId}-${index}">
            <div class="detection-header">
              <span class="detection-category">${detection.category}</span>
              <input type="checkbox" class="detection-checkbox" 
                     ${detection.selected ? 'checked' : ''}>
            </div>
            <div class="detection-pattern">${this.escapeHtml(detection.match)}</div>
            <div class="detection-replacement">
              → ${this.escapeHtml(detection.replacement)}
            </div>
            ${detection.context ? `<div class="detection-context">${this.escapeHtml(detection.context)}</div>` : ''}
          </div>
        `;
      });
    });
    
    this.elements.detectionsList.innerHTML = html;
    
    // Add event listeners to detection items
    this.elements.detectionsList.querySelectorAll('.detection-item').forEach(item => {
      const checkbox = item.querySelector('.detection-checkbox');
      const detectionId = item.dataset.detectionId;
      
      const toggleSelection = () => {
        const detection = this.findDetectionById(detectionId);
        if (detection) {
          detection.selected = !detection.selected;
          item.classList.toggle('selected', detection.selected);
          checkbox.checked = detection.selected;
        }
      };
      
      item.addEventListener('click', (e) => {
        if (e.target !== checkbox) {
          toggleSelection();
        }
      });
      
      checkbox.addEventListener('change', toggleSelection);
    });
  }

  /**
   * Find detection by ID
   * @param {string} detectionId 
   * @returns {Detection|null}
   */
  findDetectionById(detectionId) {
    const [ruleId, index] = detectionId.split('-');
    return this.state.currentDetections.find((d, i) => 
      d.ruleId === ruleId && i === parseInt(index)
    );
  }

  /**
   * Select/deselect all detections
   * @param {boolean} selected 
   */
  selectAllDetections(selected) {
    this.state.currentDetections.forEach(detection => {
      detection.selected = selected;
    });
    this.updateDetectionPanel(this.state.currentDetections);
  }

  /**
   * Clear all inputs and outputs
   */
  clearAll() {
    this.elements.inputText.value = '';
    this.elements.outputText.value = '';
    this.state.currentDetections = [];
    this.updateDetectionPanel([]);
    this.elements.inputCounter.textContent = '0 characters';
    this.updateProcessingStatus('Ready');
  }

  /**
   * Switch to a different profile
   * @param {string} profileName 
   */
  switchProfile(profileName) {
    const profileData = window.storage.loadProfile(profileName);
    if (profileData) {
      this.currentRules = profileData.rules;
      window.storage.setCurrentProfile(profileName);
      
      // Re-process current input if any
      const inputText = this.elements.inputText.value;
      if (inputText.trim()) {
        this.performDetection(inputText);
      }
      
      this.showNotification(`Switched to profile: ${profileName}`, 'success');
    } else {
      this.showNotification('Failed to load profile', 'error');
    }
  }

  /**
   * Apply theme
   * @param {string} theme 
   */
  applyTheme(theme) {
    document.body.className = `theme-${theme}`;
  }

  /**
   * Save current settings
   */
  saveCurrentSettings() {
    const settings = window.storage.getSettings();
    settings.theme = this.elements.themeSelect.value;
    settings.realTimeProcessing = this.state.realTimeEnabled;
    settings.deterministicReplacement = this.state.deterministicEnabled;
    window.storage.saveSettings(settings);
  }

  /**
   * Add sanitization to history
   * @param {string} input 
   * @param {string} output 
   */
  addToHistory(input, output) {
    const historyEntry = {
      timestamp: new Date(),
      inputPreview: input.substring(0, 100),
      outputPreview: output.substring(0, 100),
      detectionsCount: this.state.currentDetections.length,
      profileName: window.storage.getCurrentProfile(),
      inputSize: input.length,
      outputSize: output.length
    };
    
    window.storage.addHistoryEntry(historyEntry);
  }

  /**
   * Export output to file
   */
  exportOutput() {
    const output = this.elements.outputText.value;
    if (!output) {
      this.showNotification('No output to export', 'warning');
      return;
    }
    
    const blob = new Blob([output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sanitized-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    this.showNotification('File exported successfully', 'success');
  }

  /**
   * Update processing status
   * @param {string} status 
   */
  updateProcessingStatus(status) {
    this.elements.processingStatus.textContent = status;
    
    // Update storage usage
    const usage = window.storage.getStorageUsage();
    this.elements.storageUsage.textContent = `Storage: ${usage.percentage}%`;
    
    if (usage.percentage > 90) {
      this.elements.storageUsage.style.color = 'var(--danger-color)';
    } else if (usage.percentage > 80) {
      this.elements.storageUsage.style.color = 'var(--warning-color)';
    } else {
      this.elements.storageUsage.style.color = 'var(--text-secondary)';
    }
  }

  /**
   * Update UI state
   */
  updateUI() {
    this.updateProcessingStatus('Ready');
  }

  /**
   * Show welcome message
   */
  showWelcomeMessage() {
    console.log('Welcome to Data Sanitizer - Your privacy-focused data sanitization tool');
  }

  /**
   * Show notification to user
   * @param {string} message 
   * @param {string} type 
   */
  showNotification(message, type = 'info') {
    // For now, just log to console
    // In a full implementation, this would show a toast notification
    console.log(`[${type.toUpperCase()}] ${message}`);
  }

  /**
   * Show modal dialog
   * @param {string} title 
   * @param {string} content 
   * @param {Function} onConfirm 
   */
  showModal(title, content, onConfirm = null) {
    this.elements.modalTitle.textContent = title;
    this.elements.modalContent.innerHTML = content;
    this.elements.modalOverlay.classList.add('active');
    
    if (onConfirm) {
      this.elements.modalConfirm.onclick = () => {
        onConfirm();
        this.hideModal();
      };
    }
  }

  /**
   * Hide modal dialog
   */
  hideModal() {
    this.elements.modalOverlay.classList.remove('active');
    this.elements.modalConfirm.onclick = null;
  }

  /**
   * Escape HTML to prevent XSS
   * @param {string} text 
   * @returns {string}
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize application when script loads
window.app = new UIController();

// Make app globally available for debugging
if (typeof module !== 'undefined' && module.exports) {
  module.exports = UIController;
}