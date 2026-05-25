// =====================================================
// PhishGuard — Presentation Q&A Prep App Logic
// Search, filter, accordion, keyboard shortcuts
// =====================================================

document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('qaContainer');
    const searchInput = document.getElementById('searchInput');
    const filterBtns = document.querySelectorAll('.filter-btn');
    let currentFilter = 'all';
    let totalQuestions = 0;

    // ── Render all categories and questions ──
    function render(searchTerm = '') {
        container.innerHTML = '';
        let globalIndex = 0;
        let visibleCount = 0;
        const term = searchTerm.toLowerCase().trim();

        QA_DATA.forEach(category => {
            // Filter by category
            if (currentFilter !== 'all' && category.cat !== currentFilter) return;

            // Filter questions by search
            const filteredQs = category.questions.filter(q => {
                if (!term) return true;
                return q.q.toLowerCase().includes(term) ||
                       q.a.toLowerCase().includes(term);
            });

            if (filteredQs.length === 0) return;

            // Category header
            const header = document.createElement('div');
            header.className = 'cat-header';
            header.innerHTML = `
                <div class="cat-icon">${category.catIcon}</div>
                <h3 class="cat-title">${category.catLabel}</h3>
                <span class="cat-count">${filteredQs.length} questions</span>
            `;
            container.appendChild(header);

            // Questions
            filteredQs.forEach(q => {
                globalIndex++;
                visibleCount++;
                const card = document.createElement('div');
                card.className = 'qa-card';
                card.dataset.cat = category.cat;
                card.style.animationDelay = `${Math.min(globalIndex * 0.03, 0.3)}s`;

                const diffClass = q.difficulty === 'basic' ? 'diff-basic' :
                                  q.difficulty === 'intermediate' ? 'diff-intermediate' : 'diff-advanced';
                const diffLabel = q.difficulty.charAt(0).toUpperCase() + q.difficulty.slice(1);

                // Highlight search matches in question text
                let questionHtml = q.q;
                if (term) {
                    const regex = new RegExp(`(${escapeRegex(term)})`, 'gi');
                    questionHtml = q.q.replace(regex, '<mark style="background:rgba(99,102,241,0.3);color:#fff;padding:1px 3px;border-radius:3px;">$1</mark>');
                }

                card.innerHTML = `
                    <div class="qa-question" onclick="toggleCard(this)">
                        <span class="qa-num">${globalIndex}</span>
                        <span class="qa-text">${questionHtml}</span>
                        <span class="qa-difficulty ${diffClass}">${diffLabel}</span>
                        <svg class="qa-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="6 9 12 15 18 9"/>
                        </svg>
                    </div>
                    <div class="qa-answer">
                        <div class="qa-answer-inner">${q.a}</div>
                    </div>
                `;

                container.appendChild(card);
            });
        });

        // No results
        if (visibleCount === 0) {
            container.innerHTML = `
                <div class="no-results">
                    <div class="no-results-icon">🔍</div>
                    <div class="no-results-text">No questions found</div>
                    <div class="no-results-sub">Try a different search term or category</div>
                </div>
            `;
        }

        // Update counter
        document.getElementById('qCount').textContent = `${visibleCount} Questions`;
        document.getElementById('totalQ').textContent = visibleCount;
    }

    // ── Toggle accordion ──
    window.toggleCard = function(el) {
        const card = el.closest('.qa-card');
        const wasOpen = card.classList.contains('open');

        // Close all others
        document.querySelectorAll('.qa-card.open').forEach(c => {
            if (c !== card) c.classList.remove('open');
        });

        card.classList.toggle('open', !wasOpen);

        // Scroll into view if opening
        if (!wasOpen) {
            setTimeout(() => {
                card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }, 100);
        }
    };

    // ── Category filter ──
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.cat;
            render(searchInput.value);
        });
    });

    // ── Search with debounce ──
    let searchTimeout;
    searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            render(searchInput.value);
        }, 200);
    });

    // ── Keyboard shortcuts ──
    document.addEventListener('keydown', (e) => {
        // Ctrl+K to focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
        }

        // Escape to clear search
        if (e.key === 'Escape' && document.activeElement === searchInput) {
            searchInput.value = '';
            searchInput.blur();
            render();
        }
    });

    // ── Utility ──
    function escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // ── Count total questions ──
    QA_DATA.forEach(cat => {
        totalQuestions += cat.questions.length;
    });

    // ── Initial render ──
    render();

    // ── Smooth scroll for header shadow ──
    const header = document.querySelector('.header');
    let ticking = false;
    window.addEventListener('scroll', () => {
        if (!ticking) {
            requestAnimationFrame(() => {
                if (window.scrollY > 10) {
                    header.style.boxShadow = '0 4px 30px rgba(0,0,0,0.4)';
                } else {
                    header.style.boxShadow = 'none';
                }
                ticking = false;
            });
            ticking = true;
        }
    });
});
