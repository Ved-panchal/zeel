// Secure Messaging — Dashboard with tabbed interface

const AVATAR_COLORS = [
    'linear-gradient(135deg,#5b51e8,#7d6bf5)',
    'linear-gradient(135deg,#0fa97f,#3fd0a4)',
    'linear-gradient(135deg,#e2495e,#f5808f)',
    'linear-gradient(135deg,#d98a14,#f5b945)',
    'linear-gradient(135deg,#2b8bd4,#5fb6f0)',
    'linear-gradient(135deg,#8b5cf6,#b794f6)'
];
function avatarColor(name) {
    let h = 0;
    for (let i = 0; i < name.length; i++) h = name.charCodeAt(i) + ((h << 5) - h);
    return AVATAR_COLORS[Math.abs(h) % AVATAR_COLORS.length];
}
function initials(name) { return (name || '?').slice(0, 2).toUpperCase(); }
function esc(t) { const d = document.createElement('div'); d.textContent = t == null ? '' : t; return d.innerHTML; }
function isoTime(iso) { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }

class Dashboard {
    constructor() {
        this.me = window.CURRENT_USER;
        this.socket = null;
        this.currentPeer = null;
        this.users = [];
        this.conversations = {};
        this.unread = {};
        this.currentTab = 'messaging';
        this.logs = [];
        this.init();
    }

    init() {
        // Top bar avatar
        const me = document.getElementById('meAvatar');
        me.textContent = initials(this.me);
        me.style.background = avatarColor(this.me);

        // Sidebar avatar
        const sidebarAvatar = document.getElementById('sidebarAvatar');
        sidebarAvatar.textContent = initials(this.me);
        sidebarAvatar.style.background = avatarColor(this.me);

        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => this.switchTab(tab.dataset.tab));
        });

        document.getElementById('logoutBtn').addEventListener('click', () => this.logout());
        document.getElementById('sidebarLogoutBtn').addEventListener('click', () => this.logout());
        this.connectSocket();
        this.bindEvents();
        this.loadUsers().then(() => this.loadHistory());
        
        // Ensure messaging tab is properly initialized on load
        this.switchTab('messaging');
    }

    switchTab(tabId) {
        this.currentTab = tabId;

        // UI
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
        document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === `panel-${tabId}`));

        // Load data on first switch (removed auto-run for attacks)
        if (tabId === 'logs' && !this._logsLoaded) { this.loadLogs(); this._logsLoaded = true; }
        if (tabId === 'sysinfo' && !this._sysinfoLoaded) { this.loadSysInfo(); this._sysinfoLoaded = true; }
    }

    connectSocket() {
        this.socket = io();

        this.socket.on('new_message', (data) => {
            const peer = data.sender;
            this.cache(peer, {
                sender: peer,
                content: data.content,
                timestamp: data.timestamp,
                direction: 'received',
                integrity_verified: data.integrity_verified
            });
            if (peer === this.currentPeer) {
                this.renderThread();
            } else {
                this.unread[peer] = (this.unread[peer] || 0) + 1;
                this.showToast(`New message from ${peer}`);
                this.renderConvoList();
            }
        });

        this.socket.on('user_typing', (data) => {
            if (data.sender === this.currentPeer) {
                document.getElementById('chatSub').textContent = `${data.sender} is typing…`;
                clearTimeout(this._typingTimer);
                this._typingTimer = setTimeout(() => {
                    if (this.currentPeer) document.getElementById('chatSub').textContent = 'End-to-end encrypted conversation';
                }, 2000);
            }
        });
    }

    bindEvents() {
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.loadUsers(); this.loadHistory();
        });
        document.getElementById('sendBtn').addEventListener('click', () => this.send());

        const input = document.getElementById('messageInput');
        input.addEventListener('input', () => { this.autoGrow(input); this.updateCount(); });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.send(); return; }
            if (this.currentPeer && this.socket) this.socket.emit('typing', { recipient: this.currentPeer });
        });

        // Attack simulation
        document.getElementById('runAttackBtn').addEventListener('click', () => this.runAttacks());

        // Logs filter
        document.getElementById('logsFilter').addEventListener('click', (e) => {
            if (e.target.classList.contains('filter-btn')) {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.renderLogs(e.target.dataset.type);
            }
        });
    }

    autoGrow(el) { el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 120) + 'px'; }

    updateCount() {
        const n = document.getElementById('messageInput').value.length;
        const el = document.getElementById('charCount');
        el.textContent = `${n} / 10000`;
        el.style.color = n > 10000 ? 'var(--danger)' : n > 8000 ? 'var(--warning)' : 'var(--text-muted)';
    }

    async loadUsers() {
        try {
            const res = await fetch('/api/users');
            if (res.status === 401) { window.location.href = '/login'; return; }
            const data = await res.json();
            if (data.success) { this.users = data.users; this.renderConvoList(); }
        } catch (e) { console.error(e); }
    }

    renderConvoList() {
        const list = document.getElementById('convoList');
        if (!this.users.length) {
            list.innerHTML = '<div class="empty-convos">No other users yet.<br>Register a second account to chat.</div>';
            return;
        }
        list.innerHTML = this.users.map(u => {
            const convo = this.conversations[u] || [];
            const last = convo[convo.length - 1];
            const preview = last ? (last.direction === 'sent' ? 'You: ' : '') + last.content : 'No messages yet';
            const unread = this.unread[u] || 0;
            return `
                <div class="convo ${u === this.currentPeer ? 'active' : ''}" data-user="${u}">
                    <div class="avatar" style="background:${avatarColor(u)}">${initials(u)}</div>
                    <div class="meta">
                        <div class="name">${esc(u)}</div>
                        <div class="preview">${esc(preview)}</div>
                    </div>
                    ${unread ? `<div class="badge-count">${unread}</div>` : ''}
                </div>`;
        }).join('');
        list.querySelectorAll('.convo').forEach(el =>
            el.addEventListener('click', () => this.selectPeer(el.dataset.user)));
    }

    selectPeer(peer) {
        this.currentPeer = peer;
        this.unread[peer] = 0;

        document.getElementById('chatTitle').textContent = peer;
        document.getElementById('chatSub').textContent = 'End-to-end encrypted conversation';

        const input = document.getElementById('messageInput');
        input.disabled = false;
        input.placeholder = `Message ${peer}…`;
        document.getElementById('sendBtn').disabled = false;

        this.renderConvoList();
        this.renderThread();
        input.focus();
    }

    cache(peer, entry) {
        if (!this.conversations[peer]) this.conversations[peer] = [];
        const dup = this.conversations[peer].some(m =>
            m.timestamp === entry.timestamp && m.content === entry.content && m.direction === entry.direction);
        if (!dup) {
            this.conversations[peer].push(entry);
            this.conversations[peer].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
        }
    }

    renderThread() {
        const thread = document.getElementById('thread');
        const msgs = this.conversations[this.currentPeer] || [];

        if (!msgs.length) {
            thread.innerHTML = `
                <div class="empty-state">
                    <div class="glyph">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                        </svg>
                    </div>
                    <h3>Say hello to ${esc(this.currentPeer)}</h3>
                    <p>This is the beginning of your encrypted conversation.</p>
                </div>`;
            return;
        }

        thread.innerHTML = msgs.map(m => {
            const sent = m.direction === 'sent';
            const time = isoTime(m.timestamp);
            let badge = '';
            if (m.integrity_verified === true) {
                badge = '<span class="b-badge ok">✓ verified</span>';
            } else if (!sent && m.integrity_verified === false) {
                badge = '<span class="b-badge warn">unverified</span>';
            }
            return `
                <div class="msg-row ${sent ? 'sent' : 'received'}">
                    <div class="bubble">
                        ${esc(m.content)}
                        <div class="b-meta">${badge}<span>${time}</span></div>
                    </div>
                </div>`;
        }).join('');
        thread.scrollTop = thread.scrollHeight;
    }

    async send() {
        if (!this.currentPeer) { this.showToast('Select a recipient first', 'error'); return; }
        const input = document.getElementById('messageInput');
        const text = input.value.trim();
        if (!text) return;
        if (text.length > 10000) { this.showToast('Message too long (max 10000)', 'error'); return; }

        const btn = document.getElementById('sendBtn');
        btn.disabled = true;
        try {
            const res = await fetch('/api/messages/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient: this.currentPeer, message: text })
            });
            if (res.status === 401) { window.location.href = '/login'; return; }
            const data = await res.json();
            if (data.success) {
                this.cache(this.currentPeer, {
                    sender: 'You', content: text,
                    timestamp: data.timestamp || new Date().toISOString(),
                    direction: 'sent', integrity_verified: true
                });
                input.value = '';
                this.autoGrow(input);
                this.updateCount();
                this.renderThread();
                this.renderConvoList();
            } else {
                this.showToast(data.message || 'Failed to send', 'error');
            }
        } catch (e) {
            this.showToast('Network error while sending', 'error');
        } finally {
            btn.disabled = false;
            input.focus();
        }
    }

    async loadHistory() {
        try {
            const res = await fetch('/api/messages/receive');
            if (res.status === 401) { window.location.href = '/login'; return; }
            const data = await res.json();
            if (!data.success) return;

            data.messages.forEach(msg => {
                this.cache(msg.sender, {
                    sender: msg.sender, content: msg.content,
                    timestamp: msg.timestamp, direction: 'received',
                    integrity_verified: msg.integrity_verified
                });
                if (msg.sender !== this.currentPeer) {
                    this.unread[msg.sender] = (this.unread[msg.sender] || 0) + 1;
                }
            });

            if (this.currentPeer) this.renderThread();
            this.renderConvoList();
        } catch (e) { console.error(e); }
    }

    async runAttacks() {
        const btn = document.getElementById('runAttackBtn');
        const container = document.getElementById('attackResults');
        const user1 = document.getElementById('attackUser1').value.trim() || 'alice';
        const user2 = document.getElementById('attackUser2').value.trim() || 'bob';

        btn.disabled = true;
        btn.textContent = 'Running…';
        container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);">Running attack simulations…</div>';

        try {
            const res = await fetch('/api/attack-simulation', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user1, user2 })
            });
            const data = await res.json();
            if (!data.success) throw new Error(data.message);

            const summary = data.summary || {};
            const attacks = data.attacks || [];
            const recommendations = data.recommendations || [];

            container.innerHTML = `
                <div class="summary-box">
                    <div class="summary-item"><div class="val">${summary.total_attacks || 0}</div><div class="lbl">Total</div></div>
                    <div class="summary-item"><div class="val">${summary.prevented_attacks || 0}</div><div class="lbl">Prevented</div></div>
                    <div class="summary-item"><div class="val">${summary.successful_attacks || 0}</div><div class="lbl">Failed</div></div>
                    <div class="summary-item"><div class="val">${summary.total_attempts || 0}</div><div class="lbl">Attempts</div></div>
                </div>
                ${attacks.map(a => `
                    <div class="attack-card ${a.success ? 'fail' : 'success'}">
                        <div class="icon">
                            ${a.success
                                ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>'
                                : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
                            }
                        </div>
                        <div class="main">
                            <div class="name">${esc(a.attack_type || 'Attack')}</div>
                            <div class="detail">${esc(a.details || '')}</div>
                            ${a.mitigation ? `<div class="detail" style="color:var(--success)">${esc(a.mitigation)}</div>` : ''}
                        </div>
                        <div class="badge">${a.success ? 'SUCCEEDED' : 'PREVENTED'}</div>
                    </div>
                `).join('')}
                ${recommendations.length ? `
                    <div style="margin-top:16px;padding:12px;background:var(--accent-soft);border-radius:var(--radius-sm);font-size:12px;color:var(--accent);">
                        <strong>Recommendations:</strong> ${esc(recommendations.join('; '))}
                    </div>
                ` : ''}
            `;
        } catch (e) {
            container.innerHTML = `<div style="padding:16px;color:var(--danger);">
                <strong>Error:</strong> ${esc(e.message)}<br>
                <span style="font-size:11px;opacity:0.8;">Check the server console for full traceback.</span>
            </div>`;
        } finally {
            btn.disabled = false;
            btn.textContent = 'Run Simulations';
        }
    }

    async loadLogs() {
        const container = document.getElementById('logTable');
        container.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted);">Loading logs…</div>';

        try {
            const res = await fetch('/api/security-logs?limit=100');
            const data = await res.json();
            if (!data.success) throw new Error(data.message);

            this.logs = data.logs || [];
            this.renderLogs('all');
        } catch (e) {
            container.innerHTML = `<div style="padding:16px;color:var(--danger);">Error: ${esc(e.message)}</div>`;
        }
    }

    renderLogs(filterType) {
        const container = document.getElementById('logTable');
        const filtered = filterType === 'all'
            ? this.logs
            : this.logs.filter(l => this.logCategory(l) === filterType);

        if (!filtered.length) {
            container.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted);">No logs found.</div>';
            return;
        }

        container.innerHTML = filtered.map(l => {
            const typeClass = this.logCategory(l);
            return `
                <div class="log-row">
                    <div class="time">${isoTime(l.timestamp)}</div>
                    <div class="msg">${esc(l.detail || l.event || '')}</div>
                    <div class="type ${typeClass}">${typeClass}</div>
                </div>
            `;
        }).join('');
    }

    logCategory(log) {
        const category = (log.category || '').toLowerCase();
        if (category) return category;

        const event = (log.event || '').toLowerCase();
        const detail = (log.detail || '').toLowerCase();
        const combined = `${event} ${detail}`;
        if (/login|logout|register|auth|user:/.test(combined)) return 'auth';
        if (/encrypt|decrypt|crypto|key|aes|rsa|hmac/.test(combined)) return 'crypto';
        if (/message|sender|recipient|from:|to:/.test(combined)) return 'messaging';
        if (/attack|mitm|brute|nonce|replay/.test(combined)) return 'attack';
        if (/error|fail/.test(combined)) return 'error';
        return 'info';
    }

    async loadSysInfo() {
        const container = document.getElementById('sysinfoGrid');
        container.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted);">Loading…</div>';

        try {
            const res = await fetch('/api/system-info');
            const data = await res.json();
            if (!data.success) throw new Error(data.message);

            const crypto = data.crypto || {};
            const stats = data.stats || {};

            container.innerHTML = `
                <div class="info-card">
                    <div class="card-title">Cryptographic Parameters</div>
                    <div class="info-row"><div class="key">RSA Key Size</div><div class="val">${crypto.rsa_key_size || 2048} bits</div></div>
                    <div class="info-row"><div class="key">AES Key Size</div><div class="val">${crypto.aes_key_size || 256} bits</div></div>
                    <div class="info-row"><div class="key">Hash Algorithm</div><div class="val">${crypto.hash_algorithm || 'SHA-256'}</div></div>
                    <div class="info-row"><div class="key">PBKDF2 Iterations</div><div class="val">${crypto.pbkdf2_iterations || 200000}</div></div>
                    <div class="info-row"><div class="key">Bcrypt Rounds</div><div class="val">${crypto.bcrypt_rounds || 12}</div></div>
                    <div class="info-row"><div class="key">Session Timeout</div><div class="val">${crypto.session_timeout_minutes || 30} min</div></div>
                </div>
                <div class="info-card">
                    <div class="card-title">Your Stats</div>
                    <div class="info-row"><div class="key">Username</div><div class="val highlight">${esc(data.username || '')}</div></div>
                    <div class="info-row"><div class="key">Messages Sent</div><div class="val">${stats.messages_sent || 0}</div></div>
                    <div class="info-row"><div class="key">Messages Received</div><div class="val">${stats.messages_received || 0}</div></div>
                    <div class="info-row"><div class="key">Total Conversations</div><div class="val">${stats.total_conversations || 0}</div></div>
                    <div class="info-row"><div class="key">Unread Messages</div><div class="val">${stats.unread_messages || 0}</div></div>
                </div>
                <div class="info-card">
                    <div class="card-title">Security Limits</div>
                    <div class="info-row"><div class="key">Max Login Attempts</div><div class="val">${crypto.max_login_attempts || 5}</div></div>
                    <div class="info-row"><div class="key">Lockout Duration</div><div class="val">15 min</div></div>
                    <div class="info-row"><div class="key">Max Message Size</div><div class="val">10 KB</div></div>
                    <div class="info-row"><div class="key">Message Retention</div><div class="val">30 days</div></div>
                </div>
            `;
        } catch (e) {
            container.innerHTML = `<div style="padding:16px;color:var(--danger);">Error: ${esc(e.message)}</div>`;
        }
    }

    async logout() {
        if (!confirm('Log out of your secure session?')) return;
        try { await fetch('/api/logout', { method: 'POST' }); } catch (_) {}
        window.location.href = '/login';
    }

    showToast(msg, type = 'info') {
        const n = document.createElement('div');
        n.className = `alert alert-${type} toast`;
        n.textContent = msg;
        document.body.appendChild(n);
        setTimeout(() => { n.style.transition = 'opacity .3s'; n.style.opacity = '0'; }, 3000);
        setTimeout(() => { if (n.parentNode) n.remove(); }, 3400);
    }
}

document.addEventListener('DOMContentLoaded', () => { window.dashboard = new Dashboard(); });
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && window.dashboard) window.dashboard.loadHistory();
});
