/**
 * FU PERSON OSINT Finder — Main App Logic
 * Handles async search, validation, history, and exports.
 */

(function () {
    'use strict';

    const HISTORY_KEY = 'fuperson_history';
    const MAX_HISTORY = 50;

    let osintSearch;
    let authManager;

    function init() {
        if (document.getElementById('search-form')) {
            osintSearch = new OSINTSearch();
            authManager = typeof AuthManager !== 'undefined' ? new AuthManager() : null;

            bindSearchForm();
            bindExportButtons();
            bindModal();
            bindQuickLinks();
            bindUpgrade();
            loadSearchHistory();
            updatePlaceholder();

            if (authManager) authManager.updateTierDisplay();
            if (authManager && window.location.hash === '#upgrade') authManager.showSubscriptionModal();
        } else {
            bindLandingCTA();
        }
    }

    // ── INPUT VALIDATION ───────────────────────────────────

    function validateInput(type, query) {
        switch (type) {
            case 'domain': {
                const domainClean = query.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
                if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(domainClean)) {
                    return 'Invalid domain format. Example: example.com';
                }
                return null;
            }
            case 'ip': {
                const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
                const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
                if (!ipv4.test(query.trim()) && !ipv6.test(query.trim())) {
                    return 'Invalid IP address. Example: 8.8.8.8 or 2001:4860:4860::8888';
                }
                if (ipv4.test(query.trim())) {
                    const parts = query.trim().split('.');
                    if (parts.some(p => parseInt(p) > 255)) {
                        return 'Invalid IP address. Each octet must be 0-255.';
                    }
                }
                return null;
            }
            case 'email': {
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(query.trim())) {
                    return 'Invalid email format. Example: user@example.com';
                }
                return null;
            }
            case 'person': {
                if (query.trim().length < 2) {
                    return 'Enter at least 2 characters for a person search.';
                }
                return null;
            }
            case 'phone': {
                const digits = query.replace(/\D/g, '');
                if (digits.length < 7 || digits.length > 15) {
                    return 'Invalid phone number. Enter 7-15 digits. Example: +1-555-123-4567';
                }
                return null;
            }
            case 'username': {
                if (query.trim().length < 1) {
                    return 'Enter a username to search.';
                }
                if (/\s/.test(query.trim())) {
                    return 'Usernames cannot contain spaces.';
                }
                return null;
            }
            default:
                return null;
        }
    }

    // ── SEARCH FORM BINDING ────────────────────────────────

    function bindSearchForm() {
        const form = document.getElementById('search-form');
        const queryInput = document.getElementById('search-query');
        const typeSelect = document.getElementById('search-type');
        const searchBtn = document.getElementById('search-btn');

        if (!form || !osintSearch) return;

        if (typeSelect) {
            typeSelect.addEventListener('change', updatePlaceholder);
        }

        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            const query = (queryInput && queryInput.value.trim()) || '';
            const type = (typeSelect && typeSelect.value) || 'person';

            if (!query) {
                showStatus('Enter a search term', 'error');
                if (queryInput) queryInput.focus();
                return;
            }

            const validationError = validateInput(type, query);
            if (validationError) {
                showStatus(validationError, 'error');
                if (queryInput) queryInput.focus();
                return;
            }

            if (authManager && !authManager.canSearch()) {
                authManager.showSubscriptionModal();
                return;
            }

            if (osintSearch.isSearching) {
                showStatus('Search already in progress...', 'warning');
                return;
            }

            await runSearch(type, query);

            if (authManager) {
                authManager.decrementSearch();
                authManager.updateTierDisplay();
            }
        });
    }

    function updatePlaceholder() {
        const typeSelect = document.getElementById('search-type');
        const queryInput = document.getElementById('search-query');
        if (!typeSelect || !queryInput) return;

        const placeholders = {
            person: 'John Doe',
            phone: '+1-555-123-4567',
            email: 'user@example.com',
            domain: 'example.com',
            ip: '8.8.8.8',
            username: 'johndoe'
        };
        queryInput.placeholder = placeholders[typeSelect.value] || 'Enter search term...';
    }

    // ── ASYNC SEARCH RUNNER ────────────────────────────────

    async function runSearch(type, query) {
        const searchBtn = document.getElementById('search-btn');
        const searchProgress = document.getElementById('search-progress');

        osintSearch.isSearching = true;
        if (searchBtn) {
            searchBtn.disabled = true;
            searchBtn.textContent = 'Searching...';
        }
        if (searchProgress) {
            searchProgress.style.display = 'block';
        }

        osintSearch.showLoading(type, query);
        showStatus(`Searching ${type}: ${query}...`, 'info');

        try {
            let data;
            switch (type) {
                case 'person':  data = await osintSearch.searchPerson(query); break;
                case 'phone':   data = await osintSearch.searchPhone(query); break;
                case 'email':   data = await osintSearch.searchEmail(query); break;
                case 'domain':  data = await osintSearch.searchDomain(query); break;
                case 'ip':      data = await osintSearch.searchIP(query); break;
                case 'username': data = await osintSearch.searchUsername(query); break;
                default:        data = await osintSearch.searchPerson(query);
            }

            osintSearch.stopLoading();
            osintSearch.renderResults(type, data);
            showStatus(`Search complete: ${type} "${query}"`, 'success');
            addToHistory(type, query);
        } catch (err) {
            osintSearch.stopLoading();
            const resultsEl = document.getElementById('results-content');
            if (resultsEl) {
                resultsEl.innerHTML =
                    `<span class="term-prompt">root@fllc:~$</span> osint search ${type} "${escapeHtml(query)}"\n\n` +
                    `<span class="term-error">[-] Search failed: ${escapeHtml(err.message)}</span>\n` +
                    `<span class="term-info">[*] This may be due to network issues or API rate limiting.</span>\n` +
                    `<span class="term-info">[*] Please try again in a moment.</span>`;
            }
            showStatus(`Search failed: ${err.message}`, 'error');
        } finally {
            osintSearch.isSearching = false;
            if (searchBtn) {
                searchBtn.disabled = false;
                searchBtn.textContent = 'Search';
            }
            if (searchProgress) {
                searchProgress.style.display = 'none';
            }
        }
    }

    // ── STATUS BAR ─────────────────────────────────────────

    function showStatus(message, type) {
        const statusEl = document.getElementById('status-message');
        if (!statusEl) return;
        statusEl.textContent = message;
        statusEl.className = `status-${type || 'info'}`;
        if (type === 'success' || type === 'error') {
            setTimeout(() => {
                if (statusEl.textContent === message) {
                    statusEl.textContent = '';
                    statusEl.className = '';
                }
            }, 5000);
        }
    }

    // ── SEARCH HISTORY ─────────────────────────────────────

    function getHistory() {
        try {
            const saved = localStorage.getItem(HISTORY_KEY);
            return saved ? JSON.parse(saved) : [];
        } catch (e) {
            return [];
        }
    }

    function saveHistory(history) {
        try {
            localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
        } catch (e) {
            console.warn('Could not save search history', e);
        }
    }

    function addToHistory(type, query) {
        const history = getHistory();
        const entry = {
            type,
            query,
            timestamp: new Date().toISOString()
        };
        const existingIdx = history.findIndex(h => h.type === type && h.query === query);
        if (existingIdx !== -1) {
            history.splice(existingIdx, 1);
        }
        history.unshift(entry);
        saveHistory(history);
        renderSearchHistory();
    }

    function loadSearchHistory() {
        renderSearchHistory();
    }

    function renderSearchHistory() {
        const historyList = document.querySelector('.search-history');
        if (!historyList) return;

        const history = getHistory();
        historyList.innerHTML = '';

        if (history.length === 0) {
            const li = document.createElement('li');
            li.className = 'history-empty';
            li.textContent = 'No searches yet';
            historyList.appendChild(li);
            return;
        }

        history.slice(0, 20).forEach(entry => {
            const li = document.createElement('li');
            li.className = 'history-item';
            li.innerHTML = `<span class="history-type">${escapeHtml(entry.type)}:</span> <span class="history-query">${escapeHtml(entry.query)}</span>`;
            li.title = `${entry.type}: ${entry.query}\n${new Date(entry.timestamp).toLocaleString()}`;
            li.addEventListener('click', () => {
                const typeSelect = document.getElementById('search-type');
                const queryInput = document.getElementById('search-query');
                if (typeSelect) typeSelect.value = entry.type;
                if (queryInput) queryInput.value = entry.query;
                updatePlaceholder();
                document.getElementById('search-form').dispatchEvent(new Event('submit'));
            });
            historyList.appendChild(li);
        });

        if (history.length > 0) {
            const clearLi = document.createElement('li');
            clearLi.className = 'history-clear';
            clearLi.innerHTML = '<a href="#">Clear History</a>';
            clearLi.addEventListener('click', (e) => {
                e.preventDefault();
                saveHistory([]);
                renderSearchHistory();
            });
            historyList.appendChild(clearLi);
        }
    }

    // ── EXPORT BUTTONS ─────────────────────────────────────

    function bindExportButtons() {
        const exportActions = {
            'export-pdf':  { fn: () => osintSearch.exportPDF(),  gate: 'export_pdf'  },
            'export-json': { fn: () => osintSearch.exportJSON(), gate: 'export_json' },
            'export-csv':  { fn: () => osintSearch.exportCSV(),  gate: 'export_csv'  }
        };

        Object.entries(exportActions).forEach(([id, config]) => {
            const btn = document.getElementById(id);
            if (btn && osintSearch) {
                btn.addEventListener('click', () => {
                    if (!osintSearch.lastResults) {
                        showStatus('No results to export. Run a search first.', 'warning');
                        return;
                    }
                    if (authManager && !authManager.checkGatedFeature(config.gate)) {
                        showStatus(`Export to ${id.replace('export-','').toUpperCase()} requires a paid plan. Upgrade to unlock.`, 'warning');
                        authManager.showSubscriptionModal();
                        return;
                    }
                    try {
                        config.fn();
                        showStatus('Export started', 'success');
                    } catch (err) {
                        showStatus(`Export failed: ${err.message}`, 'error');
                    }
                });
            }
        });
    }

    // ── MODAL ──────────────────────────────────────────────

    function bindModal() {
        const modal = document.getElementById('subscription-modal');
        const closeBtn = document.getElementById('modal-close');
        const subscribeForm = document.getElementById('subscribe-form');

        if (closeBtn && modal) {
            closeBtn.addEventListener('click', () => {
                if (authManager) authManager.hideSubscriptionModal();
            });
        }

        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    if (authManager) authManager.hideSubscriptionModal();
                }
            });
        }

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (authManager) authManager.hideSubscriptionModal();
            }
        });

        if (subscribeForm && authManager) {
            subscribeForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const selectedTier = document.querySelector('.tier-option.tier-selected');
                const tier = selectedTier ? selectedTier.dataset.tier : 'pro';
                authManager.handleSubscribe(tier);
            });
        }

        // Tier option selection within modal
        document.querySelectorAll('.tier-option').forEach(function (opt) {
            opt.addEventListener('click', function () {
                document.querySelectorAll('.tier-option').forEach(function (o) { o.classList.remove('tier-selected'); });
                opt.classList.add('tier-selected');
                const price = opt.dataset.tier === 'elite' ? '$29.99' : '$9.99';
                const priceEl = document.getElementById('subscribe-price');
                if (priceEl) priceEl.textContent = price;
            });
        });

        // Default to pro selected
        const defaultTier = document.getElementById('tier-opt-pro');
        if (defaultTier) defaultTier.classList.add('tier-selected');
    }

    // ── QUICK LINKS ────────────────────────────────────────

    function bindQuickLinks() {
        const links = document.querySelectorAll('.quick-links a');
        const typeSelect = document.getElementById('search-type');
        const queryInput = document.getElementById('search-query');
        links.forEach(link => {
            link.addEventListener('click', function (e) {
                e.preventDefault();
                const type = this.getAttribute('data-type');
                if (typeSelect) typeSelect.value = type;
                updatePlaceholder();
                if (queryInput) queryInput.focus();
            });
        });
    }

    // ── UPGRADE BUTTON ─────────────────────────────────────

    function bindUpgrade() {
        const btn = document.getElementById('btn-upgrade');
        if (btn) {
            btn.addEventListener('click', () => {
                if (authManager) authManager.showSubscriptionModal();
            });
        }
    }

    // ── LANDING PAGE CTA ───────────────────────────────────

    function bindLandingCTA() {
        const cta = document.querySelector('.cta-btn');
        if (cta && cta.getAttribute('href') === 'app.html') {
            cta.addEventListener('click', function () {
                window.location.href = 'app.html';
            });
        }
    }

    // ── UTILITY ────────────────────────────────────────────

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ── INIT ───────────────────────────────────────────────

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
