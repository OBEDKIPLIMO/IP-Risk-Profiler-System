let riskChart = null;
let sourceChart = null;

async function initCharts() {
  await Promise.all([renderRiskDistribution(), renderThreatSourceBreakdown()]);
}

async function renderRiskDistribution() {
  try {
    const res = await fetch('/api/alerts');
    const data = await res.json();
    const alerts = data.data || [];

    const counts = { High: 0, Medium: 0, Low: 0 };
    alerts.forEach(a => {
      if (counts[a.severity_label] !== undefined) counts[a.severity_label]++;
    });

    const ctx = document.getElementById('riskDistributionChart');
    if (!ctx) return;

    if (riskChart) riskChart.destroy();
    riskChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['High', 'Medium', 'Low'],
        datasets: [{
          label: 'Alerts',
          data: [counts.High, counts.Medium, counts.Low],
          backgroundColor: ['#ef4444', '#f59e0b', '#22c55e'],
          borderRadius: 4,
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
          y: { beginAtZero: true, ticks: { color: '#94a3b8', precision: 0 }, grid: { color: '#1e293b' } }
        }
      }
    });
  } catch (e) {
    console.error('Risk distribution chart error:', e);
  }
}

async function renderThreatSourceBreakdown() {
  try {
    const res = await fetch('/api/threats');
    const data = await res.json();
    const threats = data.data || [];

    const counts = {};
    threats.forEach(t => {
      const src = t.source_api || 'Unknown';
      counts[src] = (counts[src] || 0) + 1;
    });

    const ctx = document.getElementById('threatSourceChart');
    if (!ctx) return;

    if (sourceChart) sourceChart.destroy();
    sourceChart = new Chart(ctx, {
      type: 'pie',
      data: {
        labels: Object.keys(counts),
        datasets: [{
          data: Object.values(counts),
          backgroundColor: ['#3b82f6', '#8b5cf6', '#f59e0b', '#22c55e', '#ef4444'],
          borderColor: '#0b111e',
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
      }
    });
  } catch (e) {
    console.error('Threat source chart error:', e);
  }
}

document.addEventListener('DOMContentLoaded', initCharts);
setInterval(initCharts, 60000);