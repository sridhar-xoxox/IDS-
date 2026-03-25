/* ================================================================
   Net IDS — Main JavaScript
   ================================================================ */

// ─── Live Clock ──────────────────────────────────────────────────
function updateClock() {
    const el = document.getElementById('topbarTime');
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ─── Sidebar Toggle ──────────────────────────────────────────────
const sidebarToggle = document.getElementById('sidebarToggle');
const sidebar = document.getElementById('sidebar');
if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });
    // Close on outside click on mobile
    document.addEventListener('click', (e) => {
        if (window.innerWidth <= 768 && sidebar.classList.contains('open')) {
            if (!sidebar.contains(e.target) && e.target !== sidebarToggle) {
                sidebar.classList.remove('open');
            }
        }
    });
}

// ─── Info Modal ──────────────────────────────────────────────────
function showInfo() {
    const modal = document.getElementById('infoModal');
    if (modal) modal.style.display = 'flex';
}
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        const modal = document.getElementById('infoModal');
        if (modal) modal.style.display = 'none';
    }
});

// ─── Flash auto-dismiss ──────────────────────────────────────────
document.querySelectorAll('.flash').forEach(flash => {
    setTimeout(() => {
        flash.style.transition = 'opacity .4s';
        flash.style.opacity = '0';
        setTimeout(() => flash.remove(), 400);
    }, 5000);
});

// ─── Animated entry ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Animate cards on load
    const cards = document.querySelectorAll('.kpi-card, .method-card, .chart-card, .recent-card, .result-section, .result-hero');
    cards.forEach((card, i) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(12px)';
        card.style.transition = `opacity .4s ease ${i * 0.07}s, transform .4s ease ${i * 0.07}s`;
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            });
        });
    });
});
