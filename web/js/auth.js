/**
 * FU PERSON OSINT Finder — Mock Auth & Subscription Module
 */

class AuthManager {
    constructor() {
        this.currentTier = 'free';
        this.searchesRemaining = 3;
        this.searchesToday = 0;
        this.maxSearchesFree = 3;
    }

    canSearch() {
        if (this.currentTier === 'pro' || this.currentTier === 'elite') return true;
        return this.searchesRemaining > 0;
    }

    decrementSearch() {
        if (this.currentTier === 'free') {
            this.searchesRemaining = Math.max(0, this.searchesRemaining - 1);
            this.searchesToday++;
        }
    }

    showSubscriptionModal() {
        const modal = document.getElementById('subscription-modal');
        if (modal) {
            modal.setAttribute('aria-hidden', 'false');
        }
    }

    hideSubscriptionModal() {
        const modal = document.getElementById('subscription-modal');
        if (modal) {
            modal.setAttribute('aria-hidden', 'true');
        }
    }

    showLoginForm() {
        alert('Mock login — no auth backend configured');
    }

    handleSubscribe(tier) {
        const btn = document.querySelector('.subscribe-btn');
        if (btn) btn.textContent = 'Processing...';
        setTimeout(() => {
            this.currentTier = tier || 'pro';
            this.searchesRemaining = 999;
            this.hideSubscriptionModal();
            this.updateTierDisplay();
            if (btn) btn.textContent = 'Subscribe Now';
            alert('Subscription activated! Welcome to Pro.');
        }, 1500);
    }

    updateTierDisplay() {
        const el = document.getElementById('tier-info');
        if (!el) return;
        if (this.currentTier === 'free') {
            el.textContent = `FREE TIER — ${this.searchesRemaining}/${this.maxSearchesFree} searches remaining`;
        } else {
            el.textContent = `${this.currentTier.toUpperCase()} TIER — Unlimited searches`;
        }
    }

    checkGatedFeature(feature) {
        if (feature === 'export') return this.currentTier !== 'free';
        if (feature === 'api') return this.currentTier === 'elite';
        return false;
    }
}
