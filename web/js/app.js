/**
 * FU PERSON OSINT Finder — Main App Logic
 */

(function () {
    'use strict';

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

            if (authManager) authManager.updateTierDisplay();
            if (authManager && window.location.hash === '#upgrade') authManager.showSubscriptionModal();
        } else {
            bindLandingCTA();
        }
    }

    function bindSearchForm() {
        const form = document.getElementById('search-form');
        const queryInput = document.getElementById('search-query');
        const typeSelect = document.getElementById('search-type');

        if (!form || !osintSearch) return;

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            const query = (queryInput && queryInput.value.trim()) || '';
            const type = (typeSelect && typeSelect.value) || 'person';

            if (!query) {
                alert('Enter a search term');
                return;
            }

            if (authManager && !authManager.canSearch()) {
                authManager.showSubscriptionModal();
                return;
            }

            runSearch(type, query);
            if (authManager) authManager.decrementSearch();
            if (authManager) authManager.updateTierDisplay();
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' && document.activeElement === queryInput) {
                form.dispatchEvent(new Event('submit'));
            }
        });
    }

    function runSearch(type, query) {
        let data;
        switch (type) {
            case 'person': data = osintSearch.searchPerson(query); break;
            case 'phone': data = osintSearch.searchPhone(query); break;
            case 'email': data = osintSearch.searchEmail(query); break;
            case 'domain': data = osintSearch.searchDomain(query); break;
            case 'ip': data = osintSearch.searchIP(query); break;
            case 'username': data = osintSearch.searchUsername(query); break;
            default: data = osintSearch.searchPerson(query);
        }
        osintSearch.renderResults(type, data);
    }

    function bindExportButtons() {
        ['export-pdf', 'export-json', 'export-csv'].forEach(id => {
            const btn = document.getElementById(id);
            if (btn && osintSearch) {
                btn.addEventListener('click', () => {
                    if (id === 'export-pdf') osintSearch.exportPDF();
                    else if (id === 'export-json') osintSearch.exportJSON();
                    else osintSearch.exportCSV();
                });
            }
        });
    }

    function bindModal() {
        const modal = document.getElementById('subscription-modal');
        const closeBtn = document.getElementById('modal-close');
        const subscribeForm = document.getElementById('subscribe-form');

        if (closeBtn && modal) {
            closeBtn.addEventListener('click', () => {
                if (authManager) authManager.hideSubscriptionModal();
            });
        }

        if (subscribeForm && authManager) {
            subscribeForm.addEventListener('submit', function (e) {
                e.preventDefault();
                authManager.handleSubscribe('pro');
            });
        }
    }

    function bindQuickLinks() {
        const links = document.querySelectorAll('.quick-links a');
        const typeSelect = document.getElementById('search-type');
        const queryInput = document.getElementById('search-query');
        links.forEach(link => {
            link.addEventListener('click', function (e) {
                e.preventDefault();
                const type = this.getAttribute('data-type');
                if (typeSelect) typeSelect.value = type;
                if (queryInput) queryInput.focus();
            });
        });
    }

    function bindUpgrade() {
        const btn = document.getElementById('btn-upgrade');
        if (btn) {
            btn.addEventListener('click', () => {
                if (authManager) authManager.showSubscriptionModal();
            });
        }
    }

    function bindLandingCTA() {
        const cta = document.querySelector('.cta-btn');
        if (cta && cta.getAttribute('href') === 'app.html') {
            cta.addEventListener('click', function () {
                window.location.href = 'app.html';
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
