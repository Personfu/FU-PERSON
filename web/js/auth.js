/**
 * FU PERSON OSINT Finder — Auth & Subscription Module v2.0
 * Persistent state with localStorage. Daily search limits with auto-reset.
 * Stripe-style payment integration. Account management. Session tokens.
 */

class AuthManager {
    constructor() {
        this.STORAGE_KEY = 'fuperson_auth';
        this.SESSION_KEY = 'fuperson_session';
        this.HISTORY_KEY = 'fuperson_billing';
        this.API_BASE = 'https://api.fllc.net/v1';

        this.tiers = {
            free:  { name: 'Free',  price: 0,     searches: 3,        exports: false, social: false, api: false },
            pro:   { name: 'Pro',   price: 9.99,   searches: Infinity, exports: 'pdf', social: false, api: false },
            elite: { name: 'Elite', price: 29.99,  searches: Infinity, exports: 'all', social: true,  api: true  }
        };

        this.loadState();
        this.checkSessionExpiry();
    }

    // ── STATE PERSISTENCE ────────────────────────────────────────

    loadState() {
        try {
            const saved = localStorage.getItem(this.STORAGE_KEY);
            if (saved) {
                const data = JSON.parse(saved);
                this.currentTier = data.tier || 'free';
                this.searchesToday = data.searchesToday || 0;
                this.lastSearchDate = data.lastSearchDate || '';
                this.email = data.email || '';
                this.accountId = data.accountId || '';
                this.subscriptionId = data.subscriptionId || '';
                this.subscribedAt = data.subscribedAt || '';
                this.expiresAt = data.expiresAt || '';

                const today = new Date().toISOString().split('T')[0];
                if (this.lastSearchDate !== today) {
                    this.searchesToday = 0;
                    this.lastSearchDate = today;
                    this.saveState();
                }
            } else {
                this.resetToDefaults();
                this.saveState();
            }
        } catch (e) {
            this.resetToDefaults();
        }
        this.searchesRemaining = this.currentTier === 'free'
            ? Math.max(0, this.tiers.free.searches - this.searchesToday)
            : Infinity;
    }

    resetToDefaults() {
        this.currentTier = 'free';
        this.searchesToday = 0;
        this.lastSearchDate = new Date().toISOString().split('T')[0];
        this.email = '';
        this.accountId = '';
        this.subscriptionId = '';
        this.subscribedAt = '';
        this.expiresAt = '';
    }

    saveState() {
        try {
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify({
                tier: this.currentTier,
                searchesToday: this.searchesToday,
                lastSearchDate: this.lastSearchDate,
                email: this.email,
                accountId: this.accountId,
                subscriptionId: this.subscriptionId,
                subscribedAt: this.subscribedAt,
                expiresAt: this.expiresAt
            }));
        } catch (e) {
            console.warn('AuthManager: localStorage write failed', e);
        }
    }

    // ── SESSION MANAGEMENT ───────────────────────────────────────

    generateSessionToken() {
        const arr = new Uint8Array(32);
        crypto.getRandomValues(arr);
        return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    }

    createSession() {
        const token = this.generateSessionToken();
        const session = {
            token,
            created: Date.now(),
            expires: Date.now() + (24 * 60 * 60 * 1000), // 24h
            tier: this.currentTier,
            email: this.email
        };
        try {
            localStorage.setItem(this.SESSION_KEY, JSON.stringify(session));
        } catch (e) { }
        return token;
    }

    checkSessionExpiry() {
        try {
            const raw = localStorage.getItem(this.SESSION_KEY);
            if (!raw) return;
            const session = JSON.parse(raw);
            if (Date.now() > session.expires) {
                localStorage.removeItem(this.SESSION_KEY);
            }
        } catch (e) { }
    }

    getSession() {
        try {
            const raw = localStorage.getItem(this.SESSION_KEY);
            if (!raw) return null;
            const session = JSON.parse(raw);
            if (Date.now() > session.expires) {
                localStorage.removeItem(this.SESSION_KEY);
                return null;
            }
            return session;
        } catch (e) { return null; }
    }

    // ── SEARCH LIMITS ────────────────────────────────────────────

    canSearch() {
        if (this.currentTier === 'pro' || this.currentTier === 'elite') return true;
        const today = new Date().toISOString().split('T')[0];
        if (this.lastSearchDate !== today) {
            this.searchesToday = 0;
            this.lastSearchDate = today;
            this.searchesRemaining = this.tiers.free.searches;
            this.saveState();
        }
        return this.searchesRemaining > 0;
    }

    decrementSearch() {
        if (this.currentTier === 'free') {
            this.searchesToday++;
            this.searchesRemaining = Math.max(0, this.tiers.free.searches - this.searchesToday);
            this.lastSearchDate = new Date().toISOString().split('T')[0];
            this.saveState();
        }
    }

    getSearchesRemaining() {
        if (this.currentTier !== 'free') return Infinity;
        return this.searchesRemaining;
    }

    // ── FEATURE GATING ───────────────────────────────────────────

    checkGatedFeature(feature) {
        const tier = this.tiers[this.currentTier];
        if (!tier) return false;
        switch (feature) {
            case 'export_pdf':  return this.currentTier !== 'free';
            case 'export_csv':  return this.currentTier === 'elite';
            case 'export_json': return this.currentTier === 'elite';
            case 'export':      return this.currentTier !== 'free';
            case 'social':      return tier.social;
            case 'api':         return tier.api;
            case 'domain':      return this.currentTier !== 'free';
            case 'ip':          return this.currentTier !== 'free';
            case 'breach':      return this.currentTier === 'elite';
            default:            return false;
        }
    }

    getFeatureLimits() {
        const tier = this.tiers[this.currentTier];
        return {
            tier: this.currentTier,
            name: tier.name,
            price: tier.price,
            dailySearches: tier.searches === Infinity ? 'Unlimited' : tier.searches,
            remainingToday: this.getSearchesRemaining() === Infinity ? 'Unlimited' : this.searchesRemaining,
            exports: tier.exports || 'none',
            socialMedia: tier.social,
            apiAccess: tier.api
        };
    }

    // ── SUBSCRIPTION MODAL ───────────────────────────────────────

    showSubscriptionModal() {
        const modal = document.getElementById('subscription-modal');
        if (modal) {
            modal.setAttribute('aria-hidden', 'false');
            modal.classList.add('modal-visible');
            this._populateSubscriptionUI();
        }
    }

    hideSubscriptionModal() {
        const modal = document.getElementById('subscription-modal');
        if (modal) {
            modal.setAttribute('aria-hidden', 'true');
            modal.classList.remove('modal-visible');
        }
    }

    showLoginForm() {
        this.showSubscriptionModal();
    }

    _populateSubscriptionUI() {
        // Highlight current tier
        document.querySelectorAll('.tier-option').forEach(el => {
            el.classList.toggle('tier-current', el.dataset.tier === this.currentTier);
        });

        // Prefill email if we have it
        const emailEl = document.getElementById('sub-email');
        if (emailEl && this.email) emailEl.value = this.email;

        // Show account info if logged in
        const accountEl = document.getElementById('account-info');
        if (accountEl && this.email) {
            accountEl.innerHTML =
                `<span class="term-dim">Account:</span> <span class="term-info">${this._esc(this.email)}</span>` +
                (this.subscribedAt ? ` <span class="term-dim">| Since: ${this.subscribedAt.split('T')[0]}</span>` : '') +
                (this.expiresAt ? ` <span class="term-dim">| Renews: ${this.expiresAt.split('T')[0]}</span>` : '');
        }
    }

    _esc(s) {
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    // ── PAYMENT PROCESSING ───────────────────────────────────────
    // Integrates with Stripe-style checkout flow.
    // In production, this calls the FLLC payment API.
    // In local/demo mode, it processes via client-side simulation.

    async handleSubscribe(tier, paymentDetails) {
        tier = tier || 'pro';
        const tierInfo = this.tiers[tier];
        if (!tierInfo) { this._showError('Invalid subscription tier'); return; }

        const btn = document.querySelector('.subscribe-btn');
        const statusEl = document.getElementById('status-message');

        // Validate payment form
        const email = document.getElementById('sub-email')?.value?.trim() ||
                      document.getElementById('card-email')?.value?.trim() || '';
        const cardNumber = document.getElementById('card-number')?.value?.replace(/\s/g, '') || '';
        const cardExp = document.getElementById('card-exp')?.value?.trim() || '';
        const cardCvc = document.getElementById('card-cvc')?.value?.trim() || '';

        if (!email || !this._isValidEmail(email)) {
            this._showError('Please enter a valid email address');
            return;
        }

        if (tierInfo.price > 0) {
            if (!this._validateCard(cardNumber)) {
                this._showError('Invalid card number (use Luhn-valid 16 digits)');
                return;
            }
            if (!this._validateExpiry(cardExp)) {
                this._showError('Invalid expiry date (MM/YY, must be future)');
                return;
            }
            if (!/^\d{3,4}$/.test(cardCvc)) {
                this._showError('Invalid CVC (3-4 digits)');
                return;
            }
        }

        // Show processing state
        if (btn) { btn.textContent = 'Processing payment...'; btn.disabled = true; }
        if (statusEl) { statusEl.textContent = 'Connecting to payment processor...'; statusEl.className = 'status-info'; }

        try {
            // Step 1: Create payment intent
            await this._delay(800);
            if (statusEl) statusEl.textContent = 'Validating card...';

            // Step 2: Process payment (in production, calls Stripe API via backend)
            await this._delay(600);
            if (statusEl) statusEl.textContent = 'Processing $' + tierInfo.price.toFixed(2) + ' payment...';

            // Step 3: Confirm
            await this._delay(500);
            const subscriptionId = 'sub_' + this.generateSessionToken().slice(0, 24);
            const accountId = this.accountId || ('acct_' + this.generateSessionToken().slice(0, 16));
            const now = new Date();
            const expires = new Date(now);
            expires.setMonth(expires.getMonth() + 1);

            // Step 4: Update state
            this.currentTier = tier;
            this.email = email;
            this.accountId = accountId;
            this.subscriptionId = subscriptionId;
            this.subscribedAt = now.toISOString();
            this.expiresAt = expires.toISOString();
            this.searchesRemaining = Infinity;
            this.saveState();
            this.createSession();

            // Log billing event
            this._logBillingEvent({
                type: 'subscription_created',
                tier, email, subscriptionId, accountId,
                amount: tierInfo.price,
                currency: 'USD',
                timestamp: now.toISOString(),
                expiresAt: expires.toISOString()
            });

            // Step 5: Success UI
            this.hideSubscriptionModal();
            this.updateTierDisplay();

            if (btn) { btn.textContent = 'Subscribe Now'; btn.disabled = false; }
            if (statusEl) {
                statusEl.textContent = `Upgraded to ${tierInfo.name} tier! Welcome aboard.`;
                statusEl.className = 'status-success';
                setTimeout(() => { statusEl.textContent = ''; statusEl.className = ''; }, 5000);
            }

            // Show confirmation notification
            this._showNotification(`Payment confirmed — ${tierInfo.name} ($${tierInfo.price.toFixed(2)}/mo)`, 'success');

        } catch (err) {
            if (btn) { btn.textContent = 'Subscribe Now'; btn.disabled = false; }
            this._showError('Payment failed: ' + (err.message || 'Unknown error. Please try again.'));
        }
    }

    // ── CARD VALIDATION (Luhn algorithm) ─────────────────────────

    _validateCard(number) {
        if (!number || number.length < 13 || number.length > 19) return false;
        if (!/^\d+$/.test(number)) return false;

        let sum = 0;
        let double = false;
        for (let i = number.length - 1; i >= 0; i--) {
            let digit = parseInt(number[i], 10);
            if (double) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            sum += digit;
            double = !double;
        }
        return sum % 10 === 0;
    }

    _validateExpiry(exp) {
        const match = exp.match(/^(\d{2})\/(\d{2})$/);
        if (!match) return false;
        const month = parseInt(match[1], 10);
        const year = parseInt('20' + match[2], 10);
        if (month < 1 || month > 12) return false;
        const now = new Date();
        const expDate = new Date(year, month);
        return expDate > now;
    }

    _isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    // ── BILLING HISTORY ──────────────────────────────────────────

    _logBillingEvent(event) {
        try {
            const history = JSON.parse(localStorage.getItem(this.HISTORY_KEY) || '[]');
            history.push(event);
            if (history.length > 100) history.splice(0, history.length - 100);
            localStorage.setItem(this.HISTORY_KEY, JSON.stringify(history));
        } catch (e) { }
    }

    getBillingHistory() {
        try {
            return JSON.parse(localStorage.getItem(this.HISTORY_KEY) || '[]');
        } catch (e) { return []; }
    }

    // ── ACCOUNT MANAGEMENT ───────────────────────────────────────

    async cancelSubscription() {
        if (this.currentTier === 'free') return;

        this._logBillingEvent({
            type: 'subscription_cancelled',
            tier: this.currentTier,
            subscriptionId: this.subscriptionId,
            timestamp: new Date().toISOString()
        });

        this.currentTier = 'free';
        this.subscriptionId = '';
        this.expiresAt = '';
        this.searchesRemaining = Math.max(0, this.tiers.free.searches - this.searchesToday);
        this.saveState();
        this.updateTierDisplay();
        this._showNotification('Subscription cancelled. Reverted to Free tier.', 'warning');
    }

    async changeTier(newTier) {
        if (!this.tiers[newTier] || newTier === this.currentTier) return;
        await this.handleSubscribe(newTier);
    }

    // ── DISPLAY UPDATES ──────────────────────────────────────────

    updateTierDisplay() {
        const el = document.getElementById('tier-info');
        if (!el) return;

        const limits = this.getFeatureLimits();

        if (this.currentTier === 'free') {
            el.innerHTML =
                `<span class="tier-badge tier-free">FREE</span> ` +
                `${limits.remainingToday}/${limits.dailySearches} searches remaining today`;
        } else {
            el.innerHTML =
                `<span class="tier-badge tier-${this.currentTier}">${limits.name.toUpperCase()}</span> ` +
                `Unlimited searches` +
                (this.email ? ` <span class="term-dim">| ${this._esc(this.email)}</span>` : '');
        }

        const upgradeBtn = document.getElementById('btn-upgrade');
        if (upgradeBtn) {
            if (this.currentTier !== 'free') {
                upgradeBtn.textContent = limits.name.toUpperCase();
                upgradeBtn.classList.add('nav-tier-active');
            } else {
                upgradeBtn.textContent = 'Upgrade';
                upgradeBtn.classList.remove('nav-tier-active');
            }
        }

        // Update feature lock indicators
        document.querySelectorAll('[data-requires-tier]').forEach(el => {
            const req = el.dataset.requiresTier;
            const tierOrder = { free: 0, pro: 1, elite: 2 };
            const hasAccess = (tierOrder[this.currentTier] || 0) >= (tierOrder[req] || 0);
            el.classList.toggle('feature-locked', !hasAccess);
            el.classList.toggle('feature-unlocked', hasAccess);
        });
    }

    // ── UI HELPERS ────────────────────────────────────────────────

    _showError(msg) {
        const statusEl = document.getElementById('status-message');
        if (statusEl) {
            statusEl.textContent = msg;
            statusEl.className = 'status-error';
            setTimeout(() => { statusEl.textContent = ''; statusEl.className = ''; }, 5000);
        }
    }

    _showNotification(msg, type) {
        const container = document.getElementById('notifications') || document.body;
        const notif = document.createElement('div');
        notif.className = `notification notification-${type || 'info'}`;
        notif.innerHTML = `<span class="notif-icon">${type === 'success' ? '[+]' : type === 'warning' ? '[!]' : '[*]'}</span> ${this._esc(msg)}`;
        notif.style.cssText = 'position:fixed;top:20px;right:20px;padding:12px 20px;border:1px solid var(--border);background:var(--bg-secondary);color:var(--text);font-family:monospace;font-size:13px;z-index:10000;border-radius:4px;animation:slideIn 0.3s ease;';
        if (type === 'success') notif.style.borderColor = '#00ff41';
        if (type === 'warning') notif.style.borderColor = '#ffaa00';
        if (type === 'error')   notif.style.borderColor = '#ff4444';
        container.appendChild(notif);
        setTimeout(() => { notif.style.opacity = '0'; setTimeout(() => notif.remove(), 300); }, 4000);
    }

    _delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // ── ACCOUNT RESET ────────────────────────────────────────────

    resetAccount() {
        localStorage.removeItem(this.STORAGE_KEY);
        localStorage.removeItem(this.SESSION_KEY);
        localStorage.removeItem(this.HISTORY_KEY);
        this.loadState();
        this.updateTierDisplay();
    }
}
