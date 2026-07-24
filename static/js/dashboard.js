document.addEventListener('DOMContentLoaded', () => {

    const API_BASE = '';

    function updateKPI(id, value, suffix) {
        const el = document.getElementById(id);
        if (el) el.textContent = (value || 0).toLocaleString() + (suffix || '');
    }

    function animateValue(id, start, end, duration) {
        const obj = document.getElementById(id);
        if (!obj) return;
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.textContent = Math.floor(progress * (end - start) + start).toLocaleString();
            if (progress < 1) window.requestAnimationFrame(step);
        };
        window.requestAnimationFrame(step);
    }

    function getSeverityColor(sev) {
        const map = { critical: '#ef4444', high: '#f59e0b', medium: '#3b82f6', low: '#10b981' };
        return map[sev.toLowerCase()] || '#6b7280';
    }

    // Load stats from API
    fetch(API_BASE + '/api/stats')
        .then(r => r.json())
        .then(data => {
            animateValue('kpi-hosts', 0, data.total_hosts || 0, 800);
            animateValue('kpi-scans', 0, data.total_scans || 0, 800);

            const sev = data.alerts_by_severity || {};
            const totalAlerts = Object.values(sev).reduce((a, b) => a + b, 0);
            animateValue('kpi-alerts', 0, totalAlerts, 800);
            updateKPI('kpi-risk', Math.min(totalAlerts * 10, 100), '');

            // Severity doughnut chart
            const labels = Object.keys(sev);
            const values = Object.values(sev);
            if (labels.length > 0 && document.getElementById('severityChart')) {
                createDoughnutChart('severityChart', labels, values, labels.map(l => getSeverityColor(l)));
            }
        })
        .catch(err => console.warn('Failed to load stats:', err));

    // Load recent alerts
    fetch(API_BASE + '/api/alerts/recent')
        .then(r => r.json())
        .then(alerts => {
            const tbody = document.querySelector('#alerts-table tbody');
            if (!tbody) return;
            tbody.innerHTML = '';
            if (alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No alerts yet. Run a scan to detect threats.</td></tr>';
                return;
            }
            alerts.forEach(a => {
                const tr = document.createElement('tr');
                const timeAgo = a.detected_at ? new Date(a.detected_at + 'Z').toLocaleString() : '-';
                tr.innerHTML = `
                    <td><span class="badge badge--${a.severity}"><span class="badge-dot"></span>${a.severity}</span></td>
                    <td>${a.rule_name}</td>
                    <td><code>${a.mitre_technique_id || '-'}</code></td>
                    <td>${timeAgo}</td>
                    <td><a href="/investigations/${a.session_id || ''}" class="table-action"><i class="fa-solid fa-chevron-right"></i></a></td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => console.warn('Failed to load alerts:', err));

    // Load risk trend chart
    fetch(API_BASE + '/api/risk-trend')
        .then(r => r.json())
        .then(data => {
            const labels = data.labels || [];
            const values = data.data || [];
            if (labels.length > 0 && document.getElementById('trendChart')) {
                createLineChart('trendChart', labels, values, 'Alerts', 'rgba(59, 130, 246, 1)');
            }
        })
        .catch(err => console.warn('Failed to load trend:', err));

    // Buttons
    const btnRefresh = document.getElementById('btnRefresh');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', function () {
            const icon = this.querySelector('i');
            icon.classList.add('fa-spin');
            setTimeout(() => { location.reload(); }, 500);
        });
    }

    const btnNewScan = document.getElementById('btnNewScan');
    if (btnNewScan) {
        btnNewScan.addEventListener('click', async function () {
            this.disabled = true;
            this.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
            try {
                const resp = await fetch(API_BASE + '/api/scan', { method: 'POST' });
                const data = await resp.json();
                window.location.href = '/investigations/' + data.session_id;
            } catch (err) {
                alert('Scan failed: ' + err);
                this.disabled = false;
                this.innerHTML = '<i class="fa-solid fa-crosshairs"></i> New Scan';
            }
        });
    }
});
