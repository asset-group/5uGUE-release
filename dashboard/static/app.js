/* ============================================================
   Fuzz Dashboard — Frontend v2
   ============================================================ */

/* === Plotly Theme === */
const PLT = {
  paper_bgcolor: 'rgba(0,0,0,0)',
  plot_bgcolor:  'rgba(0,0,0,0)',
  font: { color: '#8b949e', family: 'Inter, sans-serif', size: 11 },
  margin: { l: 48, r: 16, t: 8, b: 36 },
  xaxis: {
    gridcolor: 'rgba(48,54,61,0.6)', zerolinecolor: 'rgba(48,54,61,0.6)',
    linecolor: 'rgba(48,54,61,0.6)', tickfont: { size: 10 },
  },
  yaxis: {
    gridcolor: 'rgba(48,54,61,0.6)', zerolinecolor: 'rgba(48,54,61,0.6)',
    linecolor: 'rgba(48,54,61,0.6)', tickfont: { size: 10 },
  },
  hoverlabel: { bgcolor: '#1c2333', bordercolor: '#30363d', font: { color: '#c9d1d9', size: 12 } },
};

const CFG = { responsive: true, displayModeBar: false, displaylogo: false };

const C = {
  blue: '#58a6ff', green: '#3fb950', red: '#da3633', orange: '#f0883e',
  purple: '#bc8cff', yellow: '#d29922', cyan: '#56d4dd', pink: '#f778ba',
  muted: '#8b949e',
};

const PROTOCOL_NAMES = {
  'fiveg': '5G NR',
  'bt': 'Bluetooth Classic',
  'wifi': 'Wi-Fi'
};

function formatProtocol(protocol) {
  return PROTOCOL_NAMES[protocol] || protocol || '\u2014';
}

let data = null;

/* ========== Tab System ========== */
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => switchTab(item.dataset.tab));
});

function switchTab(tab) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelector(`.nav-item[data-tab="${tab}"]`).classList.add('active');

  document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
  const panel = document.getElementById(`tab-${tab}`);
  if (panel) panel.classList.remove('hidden');

  // Trigger Plotly relayout for charts that need resizing
  requestAnimationFrame(() => {
    panel.querySelectorAll('.chart-box').forEach(div => {
      if (div.data) Plotly.Plots.resize(div);
    });
  });
}

/* ========== Logo Home ========== */
document.getElementById('logo-home').addEventListener('click', () => switchTab('overview'));

/* ========== Init ========== */
let allRuns = [];
let selectedRunId = '';

document.addEventListener('DOMContentLoaded', async () => {
  const input = document.getElementById('run-input');
  const dropdown = document.getElementById('run-dropdown');

  try {
    const res = await fetch('/api/runs');
    allRuns = await res.json();
  } catch (e) {
    console.error('Failed to load runs:', e);
  }

  function runLabel(r) { return `${r.run_id}  \u2014  ${r.timestamp}`; }

  function renderDropdown() {
    const q = input.value.toLowerCase();
    const filtered = allRuns.filter(r => {
      const text = `${r.run_id} ${r.session_id || ''} ${r.timestamp || ''} ${r.device || ''} ${r.protocol || ''}`.toLowerCase();
      return text.includes(q);
    });
    if (!filtered.length) {
      dropdown.innerHTML = '<div class="run-dropdown-item run-dropdown-empty">No matches</div>';
    } else {
      dropdown.innerHTML = filtered.map(r =>
        `<div class="run-dropdown-item${r.run_id === selectedRunId ? ' active' : ''}" data-run="${r.run_id}">${esc(r.run_id)} &mdash; ${esc(r.device || 'mediatek')} (${esc(formatProtocol(r.protocol))}) &mdash; ${esc(r.session_id || '')} &mdash; ${esc(r.timestamp || '')}</div>`
      ).join('');
    }
    dropdown.classList.remove('hidden');
  }

  function selectRun(runId) {
    selectedRunId = runId;
    const run = allRuns.find(r => r.run_id === runId);
    input.value = run ? runLabel(run) : runId;
    dropdown.classList.add('hidden');
    input.blur();
    loadRun(runId);
  }

  input.addEventListener('focus', () => {
    input.select();
    renderDropdown();
  });

  input.addEventListener('input', renderDropdown);
  input.addEventListener('blur', () => {
    setTimeout(() => {
      dropdown.classList.add('hidden');
      // Restore selected label if user didn't pick anything new
      if (selectedRunId) {
        const run = allRuns.find(r => r.run_id === selectedRunId);
        if (run) input.value = runLabel(run);
      }
    }, 150);
  });

  dropdown.addEventListener('click', e => {
    const item = e.target.closest('.run-dropdown-item[data-run]');
    if (!item) return;
    selectRun(item.dataset.run);
  });

  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { dropdown.classList.add('hidden'); input.blur(); }
  });

  const hash = window.location.hash.slice(1);
  if (hash) selectRun(hash);
});

async function loadRun(runId) {
  const dash = document.querySelectorAll('.tab-panel');
  const empty = document.getElementById('empty-state');
  const loading = document.getElementById('loading');

  if (!runId) {
    dash.forEach(p => p.classList.add('hidden'));
    empty.classList.remove('hidden');
    return;
  }

  window.location.hash = runId;
  empty.classList.add('hidden');
  loading.classList.remove('hidden');
  dash.forEach(p => p.classList.add('hidden'));

  try {
    const res = await fetch(`/api/runs/${runId}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();

    document.getElementById('session-id').textContent = data.session_id || '';
    loading.classList.add('hidden');

    renderOverview();
    renderAgent();
    renderTests();
    renderIntel();

    // Show the currently active tab
    const activeTab = document.querySelector('.nav-item.active')?.dataset.tab || 'overview';
    switchTab(activeTab);
  } catch (e) {
    console.error('Failed to load run:', e);
    loading.innerHTML = `<p style="color:var(--red)">Error: ${e.message}</p>`;
  }
}

/* ========== Overview Tab ========== */
function renderOverview() {
  const s = data.summary;

  // Timestamp
  document.getElementById('run-timestamp').textContent = s.start_time || '';

  // Hero cards
  const modelRaw = data.model || '';
  const modelShort = modelRaw.includes('/') ? modelRaw.split('/').pop() : modelRaw;

  // Research quality score
  const rq = data.research_quality || {};
  const rqLevel = rq.max_level || 'L0';
  const rqMean = rq.mean_score != null ? rq.mean_score.toFixed(2) : '—';

  const device = data.device || 'mediatek';
  const protocol = formatProtocol(data.protocol);

  const row1 = [
    { label: 'Model', value: modelShort || '\u2014', accent: 'orange' },
    { label: 'Device', value: device, accent: 'yellow' },
    { label: 'Protocol', value: protocol, accent: 'yellow' },
    { label: 'Version', value: data.version || '\u2014', accent: 'yellow' },
    { label: 'Duration', value: `${s.duration_min}m`, accent: 'muted' },
  ];
  const row2 = [
    { label: 'Turns', value: s.total_turns, accent: 'blue' },
    { label: 'Tests', value: s.tests_run, accent: 'cyan',
      sub: s.compile_failures > 0 ? `${s.compile_failures} compile failures` : null },
    { label: 'Crashes', value: s.total_crashes, accent: 'red',
      sub: `${s.unique_crashes} unique<br>${s.non_publicly_known} non-public · ${s.fully_novel} novel` },
    { label: 'Research Quality', value: rqLevel, accent: 'green',
      sub: `mean ${rqMean}` },
    { label: 'Tokens', value: fmtTokens(s.total_tokens), accent: 'purple',
      sub: `${fmtTokens(s.total_input_tokens)} in / ${fmtTokens(s.total_output_tokens)} out` },
  ];

  const renderRow = (cards) => cards.map(c => `
    <div class="hero-card accent-${c.accent}">
      <div class="card-label">${c.label}</div>
      <div class="card-value">${c.value}</div>
      ${c.sub ? `<div class="card-sub">${c.sub}</div>` : ''}
    </div>
  `).join('');

  document.getElementById('hero-cards').innerHTML =
    `<div class="hero-row">${renderRow(row1)}</div>` +
    `<div class="hero-row">${renderRow(row2)}</div>`;

  // Turn activity strip
  renderTurnActivity(data.metrics);

  // Crash chart
  renderCrashChart(data.metrics);

  // At a glance
  renderGlance(data);
}

/* --- Tool category classification --- */
const TOOL_CATEGORIES = {
  research:  { label: 'Research',  color: '#58a6ff', tools: new Set(['web_search', 'fetch_url', 'query_papers', 'read_paper', 'list_paper_categories', 'search_fields']) },
  execution: { label: 'Execution', color: '#da3633', tools: new Set(['execute_test', 'execute_test_batch', 'submit_custom_exploit']) },
  analysis:  { label: 'Analysis',  color: '#f0883e', tools: new Set(['inspect_packets', 'list_packet_types', 'get_packet_hex', 'get_field_info', 'analyze_crash_log', 'compare_crashes', 'read_device_log', 'view_state_machine', 'list_exploits', 'read_exploit_source']) },
  device:    { label: 'Device',    color: '#56d4dd', tools: new Set(['adb_logcat', 'adb_device_state', 'adb_dmesg', 'adb_dumpsys', 'adb_modem_health']) },
  memory:    { label: 'Memory',    color: '#bc8cff', tools: new Set(['save_finding', 'query_findings', 'promote_finding', 'query_global_findings', 'get_test_history', 'update_strategy']) },
};
const CAT_ORDER = ['research', 'execution', 'analysis', 'device', 'memory'];

function classifyTurn(m) {
  const counts = {};
  CAT_ORDER.forEach(c => { counts[c] = 0; });
  (m.tools_called || []).forEach(t => {
    for (const [cat, def] of Object.entries(TOOL_CATEGORIES)) {
      if (def.tools.has(t)) { counts[cat]++; break; }
    }
  });
  return counts;
}

function renderTurnActivity(metrics) {
  const strip = document.getElementById('turn-activity');
  const legend = document.getElementById('activity-legend');
  if (!metrics.length) { strip.innerHTML = '<div class="no-data">No data</div>'; return; }

  strip.innerHTML = metrics.map(m => {
    const cats = classifyTurn(m);
    const totalCalls = Object.values(cats).reduce((a, b) => a + b, 0) || 1;
    const toolList = (m.tools_called || []).join(', ');

    // Error turns — stub rows recorded when the iteration bailed on an error
    // path (rate limit, API/LLM error, empty response) before doing any work.
    const isError = m.phase === 'error' || !!m.error;
    if (isError) {
      const reason = m.error || 'error';
      const tip = `<div class="turn-tooltip"><strong>Turn ${m.turn}</strong> &middot; <span style="color:var(--red)">error: ${reason}</span></div>`;
      return `<div class="turn-col error" title="error: ${reason}">
        <span class="turn-num">${m.turn}</span>
        <div class="cat-cells"><div class="cat-cell error-cell">!</div></div>
        ${tip}
      </div>`;
    }

    // Crash marker
    let crashDot = '';
    if (m.turn_crashes > 0) {
      const isNovel = m.turn_fully_novel > 0;
      crashDot = `<div class="crash-marker${isNovel ? ' novel' : ''}" title="${m.turn_crashes} crash(es)"></div>`;
    }

    // Category cells — intensity based on proportion of calls
    const cells = CAT_ORDER.map(cat => {
      const count = cats[cat];
      if (count === 0) return `<div class="cat-cell empty"></div>`;
      const intensity = Math.min(0.3 + (count / totalCalls) * 0.7, 1);
      const col = TOOL_CATEGORIES[cat].color;
      return `<div class="cat-cell" style="background:${col};opacity:${intensity.toFixed(2)}" title="${TOOL_CATEGORIES[cat].label}: ${count}"></div>`;
    }).join('');

    // Tooltip
    const tip = `<div class="turn-tooltip"><strong>Turn ${m.turn}</strong> &middot; ${m.tool_call_count || 0} calls<br>${toolList || 'none'}${m.turn_crashes ? `<br><span style="color:var(--red)">${m.turn_crashes} crash(es)</span>` : ''}</div>`;

    return `<div class="turn-col">
      <span class="turn-num">${m.turn}</span>
      <div class="cat-cells">${cells}</div>
      ${crashDot}
      ${tip}
    </div>`;
  }).join('');

  // Legend
  legend.innerHTML = CAT_ORDER.map(cat => {
    const def = TOOL_CATEGORIES[cat];
    return `<span class="legend-item"><span class="legend-swatch" style="background:${def.color}"></span>${def.label}</span>`;
  }).join('') + `<span class="legend-item"><span class="legend-swatch" style="background:var(--red);border-radius:50%;width:8px;height:8px"></span>Crash</span>`;
}

function renderCrashChart(metrics) {
  const div = document.getElementById('crash-chart');
  if (!metrics.length) return noData(div);

  const turns = metrics.map(m => m.turn);
  const makeLine = (key, name, color, dash) => ({
    x: turns, y: metrics.map(m => m[key]),
    type: 'scatter', mode: 'lines', name,
    line: { color, width: 2, shape: 'hv', dash: dash || 'solid' },
    fill: key === 'cumulative_crashes' ? 'tozeroy' : 'none',
    fillcolor: key === 'cumulative_crashes' ? 'rgba(218,54,51,0.08)' : undefined,
  });

  Plotly.newPlot(div, [
    makeLine('cumulative_crashes', 'Total', C.red),
    makeLine('cumulative_publicly_known', 'Publicly Known', C.yellow, 'dash'),
    makeLine('cumulative_non_publicly_known', 'Non-Public', C.purple, 'dash'),
    makeLine('cumulative_fully_novel', 'Fully Novel', C.green, 'dot'),
  ], {
    ...PLT, height: 300,
    xaxis: { ...PLT.xaxis, title: { text: 'Turn', font: { size: 10 } } },
    yaxis: { ...PLT.yaxis, title: { text: 'Cumulative Crashes', font: { size: 10 } } },
    legend: { orientation: 'h', y: 1.15, font: { size: 11 }, bgcolor: 'rgba(0,0,0,0)' },
  }, CFG);
}

function renderGlance(d) {
  const m = d.metrics;
  const researchTurns = m.filter(t => t.phase === 'research').length;
  const testingTurns = m.filter(t => t.phase === 'testing').length;
  const compileRate = d.summary.tests_run > 0
    ? Math.round(((d.summary.tests_run - d.summary.compile_failures) / d.summary.tests_run) * 100) : 0;
  const totalTools = m.reduce((s, t) => s + (t.tool_call_count || 0), 0);

  document.getElementById('at-a-glance').innerHTML = [
    { val: `${researchTurns}/${testingTurns}`, label: 'Research / Test Turns' },
    { val: `${compileRate}%`, label: 'Compile Success Rate' },
    { val: totalTools, label: 'Total Tool Calls' },
  ].map(g => `
    <div class="glance-item">
      <span class="glance-val">${g.val}</span>
      <span class="glance-label">${g.label}</span>
    </div>
  `).join('');
}

/* ========== Agent Tab ========== */
function renderAgent() {
  renderTokenChart(data.metrics);
  renderToolDonut(data.metrics);
  renderToolHeatmap(data.metrics);
}

function renderTokenChart(metrics) {
  const div = document.getElementById('token-chart');
  if (!metrics.length) return noData(div);

  const turns = metrics.map(m => m.turn);

  Plotly.newPlot(div, [
    {
      x: turns, y: metrics.map(m => m.input_tokens),
      type: 'scatter', mode: 'lines', name: 'Input',
      line: { color: C.blue, width: 1.5 },
      fill: 'tozeroy', fillcolor: 'rgba(88,166,255,0.12)',
    },
    {
      x: turns, y: metrics.map(m => m.output_tokens),
      type: 'scatter', mode: 'lines', name: 'Output',
      line: { color: C.purple, width: 1.5 },
      fill: 'tozeroy', fillcolor: 'rgba(188,140,255,0.12)',
    },
  ], {
    ...PLT, height: 300,
    xaxis: { ...PLT.xaxis, title: { text: 'Turn', font: { size: 10 } } },
    yaxis: { ...PLT.yaxis, title: { text: 'Tokens', font: { size: 10 } } },
    legend: { orientation: 'h', y: 1.12, font: { size: 11 }, bgcolor: 'rgba(0,0,0,0)' },
  }, CFG);
}

function renderToolDonut(metrics) {
  const div = document.getElementById('tool-donut');
  if (!metrics.length) return noData(div);

  const agg = {};
  metrics.forEach(m => {
    Object.entries(m.tool_counts || {}).forEach(([t, c]) => { agg[t] = (agg[t] || 0) + c; });
  });

  const sorted = Object.entries(agg).sort((a, b) => b[1] - a[1]);
  const total = sorted.reduce((s, e) => s + e[1], 0);
  const palette = [C.blue, C.red, C.green, C.orange, C.purple, C.cyan, C.yellow, C.pink, C.muted];

  Plotly.newPlot(div, [{
    labels: sorted.map(s => `${s[0]}  —  ${s[1]} (${(s[1]/total*100).toFixed(1)}%)`),
    values: sorted.map(s => s[1]),
    type: 'pie', hole: 0.55,
    marker: { colors: sorted.map((_, i) => palette[i % palette.length]), line: { color: '#161b22', width: 2 } },
    textinfo: 'percent',
    textfont: { size: 10, color: '#c9d1d9' },
    hovertemplate: '%{label}<br>%{value} calls<br>%{percent}<extra></extra>',
    sort: false,
  }], {
    ...PLT, height: 320,
    margin: { l: 10, r: 10, t: 10, b: 10 },
    showlegend: true,
    legend: { font: { size: 10 }, bgcolor: 'rgba(0,0,0,0)', x: 1, y: 0.5 },
  }, CFG);
}

function renderToolHeatmap(metrics) {
  const div = document.getElementById('tool-heatmap');
  if (!metrics.length) return noData(div);

  // Aggregate to find top tools
  const agg = {};
  metrics.forEach(m => {
    Object.entries(m.tool_counts || {}).forEach(([t, c]) => { agg[t] = (agg[t] || 0) + c; });
  });
  const topTools = Object.entries(agg).sort((a, b) => b[1] - a[1]).slice(0, 10).map(s => s[0]);

  const turns = metrics.map(m => m.turn);
  const z = topTools.map(tool =>
    metrics.map(m => (m.tool_counts || {})[tool] || 0)
  );

  Plotly.newPlot(div, [{
    x: turns, y: topTools, z,
    type: 'heatmap',
    colorscale: [[0, '#161b22'], [0.5, '#1f4068'], [1, '#58a6ff']],
    showscale: false,
    hovertemplate: 'Turn %{x}<br>%{y}: %{z} calls<extra></extra>',
    xgap: 1, ygap: 1,
  }], {
    ...PLT, height: 320,
    margin: { l: 140, r: 16, t: 8, b: 36 },
    xaxis: { ...PLT.xaxis, title: { text: 'Turn', font: { size: 10 } } },
    yaxis: { ...PLT.yaxis, automargin: true, tickfont: { size: 10 } },
  }, CFG);
}

/* ========== Tests Tab ========== */
function renderTests() {
  const tests = data.tests || [];

  // Summary bar
  const crashed = tests.filter(t => t.crash).length;
  const compiled = tests.filter(t => t.compile_success).length;
  document.getElementById('test-summary-bar').innerHTML = [
    { val: tests.length, label: 'Total Tests', color: C.blue },
    { val: crashed, label: 'Crashed', color: C.red },
    { val: compiled, label: 'Compiled', color: C.green },
  ].map(s => `
    <div class="test-stat">
      <span class="stat-dot" style="background:${s.color}"></span>
      <span class="stat-val">${s.val}</span>
      <span class="stat-label">${s.label}</span>
    </div>
  `).join('');

  // Unique crash strings by category, taking protocol-specific equivalence (like BT split by '|') into account.
  function getUniqueCrashStrings(tests, category, protocol) {
    const rawCrashes = tests
      .filter(t => t.crash_category === category && t.crash_id)
      .map(t => t.crash_id);

    const uniqueList = [];
    for (const cid of rawCrashes) {
      let exists = false;
      for (const u of uniqueList) {
        if (cid === u) {
          exists = true;
          break;
        }
        if (protocol === 'bt') {
          // For Bluetooth Classic, we check if the assertion part matches.
          const part1 = cid.split('|')[0].trim();
          const part2 = u.split('|')[0].trim();
          if (part1 && part2 && part1 === part2) {
            exists = true;
            break;
          }
        }
      }
      if (!exists) {
        uniqueList.push(cid);
      }
    }
    return uniqueList;
  }

  const publiclyKnown = getUniqueCrashStrings(tests, 'publicly_known_crash', data.protocol);
  const nonPubliclyKnown = getUniqueCrashStrings(tests, 'non_publicly_known_crash', data.protocol);


  document.getElementById('publicly-known-count').textContent = publiclyKnown.length;
  document.getElementById('publicly-known-crashes').innerHTML = publiclyKnown.length
    ? publiclyKnown.map(id => `<div class="crash-string-item">${esc(id)}</div>`).join('')
    : '<div class="no-data" style="min-height:60px">None</div>';

  document.getElementById('non-publicly-known-count').textContent = nonPubliclyKnown.length;
  document.getElementById('non-publicly-known-crashes').innerHTML = nonPubliclyKnown.length
    ? nonPubliclyKnown.map(id => `<div class="crash-string-item">${esc(id)}</div>`).join('')
    : '<div class="no-data" style="min-height:60px">None</div>';

  // Table
  const container = document.getElementById('test-table-container');
  if (!tests.length) {
    container.innerHTML = '<div class="no-data">No tests recorded.</div>';
    return;
  }

  const cols = [
    { key: 'test_id', label: 'ID' },
    { key: 'exploit_name', label: 'Exploit' },
    { key: 'llm', label: 'LLM' },
    { key: 'version', label: 'Version' },
    { key: 'crash', label: 'Crash' },
    { key: 'crash_category', label: 'Category' },
    { key: 'crash_id', label: 'Crash ID' },
    { key: 'observations', label: 'Observations' },
    { key: 'compile_success', label: 'Build' },
    { key: 'execution_time_seconds', label: 'Time' },
    { key: 'mutation_count', label: 'Mut.' },
    { key: 'total_packets', label: 'Pkts' },
  ];

  let sortCol = 'test_id', sortAsc = true;

  function extractIdSuffix(id) {
    if (!id) return 0;
    const parts = String(id).split('-');
    const last = parts[parts.length - 1];
    const num = parseInt(last, 10);
    return isNaN(num) ? 0 : num;
  }

  function render() {
    let rows = [...tests];
    if (sortCol) {
      rows.sort((a, b) => {
        if (sortCol === 'test_id') {
          const na = extractIdSuffix(a.test_id), nb = extractIdSuffix(b.test_id);
          return sortAsc ? na - nb : nb - na;
        }
        let va = a[sortCol] ?? '', vb = b[sortCol] ?? '';
        if (typeof va === 'number' && typeof vb === 'number') return sortAsc ? va - vb : vb - va;
        return sortAsc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
      });
    }

    const thead = cols.map(c =>
      `<th onclick="window._sortTests('${c.key}')" class="${sortCol === c.key ? 'sorted' : ''}">${c.label}<span class="sort-icon">${sortCol === c.key ? (sortAsc ? '\u25B2' : '\u25BC') : '\u25B2'}</span></th>`
    ).join('');

    const tbody = rows.map((t, idx) => {
      const cls = t.crash ? 'crash-row' : '';
      const detailId = `test-detail-${idx}`;
      return `<tr class="${cls} test-row-clickable" onclick="window._toggleTestDetail('${detailId}')">
        <td style="font-family:var(--mono);font-size:11px">${t.test_id || ''}</td>
        <td title="${esc(t.exploit_name || '')}">${trunc(t.exploit_name || '', 28)}</td>
        <td>${esc(t.llm || '\u2014')}</td>
        <td>${esc(t.version || '\u2014')}</td>
        <td>${t.crash ? '<span class="badge badge-crash">YES</span>' : '<span class="badge badge-no-crash">NO</span>'}</td>
        <td>${catBadge(t.crash_category, t.mutation_parse_warnings)}</td>
        <td class="wrap-cell" style="font-family:var(--mono);font-size:10px">${esc(t.crash_id || '')}</td>
        <td class="wrap-cell">${esc(t.observations || '\u2014')}</td>
        <td>${t.compile_success ? '<span class="badge badge-ok">OK</span>' : '<span class="badge badge-fail">FAIL</span>'}</td>
        <td style="text-align:right;font-family:var(--mono)">${t.execution_time_seconds != null ? t.execution_time_seconds.toFixed(1) + 's' : '\u2014'}</td>
        <td style="text-align:right;font-family:var(--mono)">${t.mutation_count ?? '\u2014'}</td>
        <td style="text-align:right;font-family:var(--mono)">${t.total_packets ?? '\u2014'}</td>
      </tr>
      <tr id="${detailId}" class="test-detail-row hidden">
        <td colspan="${cols.length}">
          <div class="test-code-container">
            <div class="test-code-header">Exploit Code &mdash; ${esc(t.exploit_name || '')}</div>
            <pre class="test-code">${esc(t.exploit_code || 'No code available.')}</pre>
          </div>${(t.mutation_parse_warnings && t.mutation_parse_warnings.length) ? `
          <div class="test-code-container" style="margin-top:8px;border-left:3px solid #e67e22;padding-left:10px">
            <div class="test-code-header" style="color:#e67e22">\u26A0 Unparsed Mutations (${t.mutation_parse_warnings.length}) &mdash; novelty check may be incomplete</div>
            <pre class="test-code" style="font-size:11px">${t.mutation_parse_warnings.map(w => esc(w)).join('\n')}</pre>
          </div>` : ''}
        </td>
      </tr>`;
    }).join('');

    container.innerHTML = `<table><thead><tr>${thead}</tr></thead><tbody>${tbody}</tbody></table>`;
  }

  window._sortTests = key => {
    if (sortCol === key) sortAsc = !sortAsc;
    else { sortCol = key; sortAsc = true; }
    render();
  };

  window._toggleTestDetail = id => {
    const row = document.getElementById(id);
    if (row) row.classList.toggle('hidden');
  };

  render();
}

function catBadge(cat, parseWarnings) {
  if (!cat) return '\u2014';
  const map = {
    'publicly_known_crash': ['Known', 'badge-publicly-known'],
    'non_publicly_known_crash': ['Non-Public', 'badge-non-public'],
    'fully_novel_crash': ['Novel', 'badge-novel'],
  };
  let [label, cls] = map[cat] || [cat, 'badge-no-crash'];
  if (cat === 'fully_novel_crash' && parseWarnings && parseWarnings.length) {
    label += ' \u26A0';
  }
  return `<span class="badge ${cls}">${label}</span>`;
}

/* ========== Intel Tab ========== */
function renderIntel() {
  const findings = data.findings || [];
  const container = document.getElementById('findings-container');

  if (!findings.length) {
    container.innerHTML = '<div class="no-data">No findings recorded.</div>';
  } else {
    container.innerHTML = findings.map(f => {
      const desc = f.description || '';
      const tags = (f.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join('');

      return `<div class="finding-card">
        <div class="finding-meta">
          <span class="finding-id">#${f.finding_id || '?'}</span>
          <span class="finding-type">${esc(f.type || '')}</span>
          <span class="finding-ts">${f.timestamp || ''}</span>
        </div>
        <div class="finding-desc">${esc(desc)}</div>
        <div class="tags">${tags}</div>
      </div>`;
    }).join('');
  }

  document.getElementById('strategy-content').textContent = data.strategy || 'No strategy file found.';

  // Reasoning
  const reasoning = data.reasoning || [];
  const reasoningContainer = document.getElementById('reasoning-container');

  if (!reasoning.length) {
    reasoningContainer.innerHTML = '<div class="no-data">No reasoning recorded.</div>';
  } else {
    reasoningContainer.innerHTML = reasoning.map((r, i) => `
      <div class="reasoning-block">
        <div class="reasoning-meta">
          <span class="reasoning-idx">#${i + 1}</span>
          <span class="reasoning-ts">${esc(r.timestamp || '')}</span>
        </div>
        <pre class="reasoning-content">${esc(r.content)}</pre>
      </div>
    `).join('');
  }
}

/* ========== Sweep Tab ========== */
let sweepData = null;
let sweepRefreshTimer = null;

// Load sweep list when tab is first activated
document.querySelector('.nav-item[data-tab="sweep"]')?.addEventListener('click', async () => {
  const sel = document.getElementById('sweep-selector');
  if (sel.options.length <= 1) {
    try {
      const res = await fetch('/api/sweeps');
      const sweeps = await res.json();
      sweeps.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.sweep_id;
        opt.textContent = `${s.sweep_id} \u2014 ${s.profile} \u2014 ${s.device} (${formatProtocol(s.protocol)}) \u2014 ${s.start_time}`;
        sel.appendChild(opt);
      });
    } catch (e) { console.error('Failed to load sweeps:', e); }
  }
});

document.getElementById('sweep-selector')?.addEventListener('change', e => {
  const id = e.target.value;
  if (id) loadSweep(id);
  else {
    document.getElementById('sweep-empty').classList.remove('hidden');
    document.getElementById('sweep-content').classList.add('hidden');
    stopSweepRefresh();
  }
});

document.getElementById('sweep-auto-refresh')?.addEventListener('change', e => {
  const sel = document.getElementById('sweep-selector');
  if (e.target.checked && sel.value) startSweepRefresh(sel.value);
  else stopSweepRefresh();
});

async function loadSweep(sweepId) {
  try {
    const res = await fetch(`/api/sweeps/${sweepId}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    sweepData = await res.json();

    document.getElementById('sweep-empty').classList.add('hidden');
    document.getElementById('sweep-content').classList.remove('hidden');

    renderSweepProgress(sweepData.progress, sweepData.manifest);
    renderSweepHeatmaps(sweepData.heatmap);
    renderSweepCrashList(sweepData.crashes);

    if (document.getElementById('sweep-auto-refresh')?.checked) {
      startSweepRefresh(sweepId);
    }
  } catch (e) {
    console.error('Failed to load sweep:', e);
  }
}

function startSweepRefresh(sweepId) {
  stopSweepRefresh();
  sweepRefreshTimer = setInterval(() => loadSweep(sweepId), 30000);
}

function stopSweepRefresh() {
  if (sweepRefreshTimer) { clearInterval(sweepRefreshTimer); sweepRefreshTimer = null; }
}

function renderSweepProgress(progress, manifest) {
  const completed = progress.tests_completed || 0;
  const total = progress.tests_total || manifest.total_combinations || 1;
  const pct = Math.min(100, (completed / total * 100)).toFixed(1);

  const bar = document.getElementById('sweep-progress-bar');
  bar.style.width = `${pct}%`;
  bar.style.background = pct >= 100 ? C.green : C.blue;

  document.getElementById('sweep-progress-text').textContent = `${completed} / ${total} (${pct}%)`;

  const avg = progress.avg_seconds_per_test || 0;
  const elapsed = progress.elapsed_seconds || 0;
  const eta = progress.eta_seconds || 0;
  const crashes = progress.crashes_found || 0;
  const unique = progress.unique_crash_ids || 0;
  const status = progress.status || (completed >= total ? 'completed' : 'running');

  const statusColor = status === 'completed' ? C.green : status === 'interrupted' ? C.orange : C.blue;

  document.getElementById('sweep-stats').innerHTML = [
    { val: fmtTime(elapsed), label: 'Elapsed', accent: 'muted' },
    { val: `${avg.toFixed(1)}s`, label: 'Avg/Test', accent: 'blue' },
    { val: eta > 0 ? fmtTime(eta) : '\u2014', label: 'ETA', accent: 'cyan' },
    { val: crashes, label: 'Crashes', accent: 'red' },
    { val: unique, label: 'Unique', accent: 'purple' },
    { val: `<span style="color:${statusColor}">${status}</span>`, label: 'Status', accent: 'muted' },
  ].map(s => `
    <div class="hero-card accent-${s.accent}" style="min-width:100px">
      <div class="card-label">${s.label}</div>
      <div class="card-value" style="font-size:18px">${s.val}</div>
    </div>
  `).join('');
}

function renderSweepHeatmaps(heatmap) {
  const container = document.getElementById('sweep-heatmap-container');
  if (!heatmap || !Object.keys(heatmap).length) {
    container.innerHTML = '<div class="no-data">No results yet</div>';
    return;
  }

  container.innerHTML = '';
  for (const [filt, data] of Object.entries(heatmap)) {
    const div = document.createElement('div');
    div.style.marginBottom = '24px';

    const title = document.createElement('div');
    title.style.cssText = 'font-size:13px;font-weight:600;color:#c9d1d9;margin-bottom:8px';
    title.textContent = filt;
    div.appendChild(title);

    const chartDiv = document.createElement('div');
    chartDiv.className = 'chart-box';
    div.appendChild(chartDiv);
    container.appendChild(div);

    // Map grid values to colors:
    // null -> NaN (shows as bg), 0 -> green, 1 -> red, -1 -> gray
    const z = data.grid.map(row => row.map(v => v === null ? NaN : v));
    const text = data.grid.map((row, ri) =>
      row.map((v, ci) => {
        const off = data.offsets[ri];
        const val = data.values_hex[ci];
        if (v === null) return `off=${off} val=${val}<br>untested`;
        if (v === -1) return `off=${off} val=${val}<br>compile fail`;
        if (v === 1) return `off=${off} val=${val}<br>CRASH`;
        return `off=${off} val=${val}<br>no crash`;
      })
    );

    Plotly.newPlot(chartDiv, [{
      x: data.values_hex,
      y: data.offsets,
      z: z,
      text: text,
      hovertemplate: '%{text}<extra></extra>',
      type: 'heatmap',
      colorscale: [
        [0, '#1a7f37'],   // -1 compile fail -> dark
        [0.5, '#3fb950'], // 0 no crash -> green
        [1, '#da3633'],   // 1 crash -> red
      ],
      zmin: -1,
      zmax: 1,
      showscale: false,
      xgap: 2,
      ygap: 1,
    }], {
      ...PLT,
      height: Math.max(200, data.offsets.length * 18 + 60),
      margin: { l: 56, r: 16, t: 8, b: 40 },
      xaxis: { ...PLT.xaxis, title: { text: 'Value', font: { size: 10 } }, type: 'category' },
      yaxis: { ...PLT.yaxis, title: { text: 'Offset', font: { size: 10 } }, autorange: 'reversed' },
    }, CFG);
  }
}

function renderSweepCrashList(crashes) {
  document.getElementById('sweep-crash-count').textContent = crashes.length;
  const container = document.getElementById('sweep-crash-table');

  if (!crashes.length) {
    container.innerHTML = '<div class="no-data" style="min-height:60px">No crashes found yet</div>';
    return;
  }

  const rows = crashes.map(c => `
    <tr class="crash-row">
      <td style="font-family:var(--mono);font-size:11px">${c.test_num || ''}</td>
      <td>${esc(c.filter || '')}</td>
      <td style="text-align:right;font-family:var(--mono)">${c.offset}</td>
      <td style="font-family:var(--mono)">${esc(c.value_hex || '')}</td>
      <td>${catBadge(c.crash_category, null)}</td>
      <td class="wrap-cell" style="font-family:var(--mono);font-size:10px">${esc(c.crash_id || '')}</td>
      <td style="text-align:right;font-family:var(--mono)">${c.execution_time_seconds != null ? c.execution_time_seconds.toFixed(1) + 's' : '\u2014'}</td>
      <td>${esc(c.timestamp || '')}</td>
    </tr>
  `).join('');

  container.innerHTML = `<table>
    <thead><tr>
      <th>#</th><th>Filter</th><th>Offset</th><th>Value</th>
      <th>Category</th><th>Crash ID</th><th>Time</th><th>Timestamp</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function fmtTime(seconds) {
  if (seconds <= 0) return '\u2014';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/* ========== Reports Tab (multi-run eval CSVs) ========== */
let reportsListLoaded = false;

document.querySelector('.nav-item[data-tab="reports"]')?.addEventListener('click', loadReportsList);

async function loadReportsList() {
  if (reportsListLoaded) return;
  const sel = document.getElementById('report-selector');
  if (!sel) return;
  try {
    const res = await fetch('/api/reports');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const reports = await res.json();
    reports.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.eval_id;
      const label = r.source_csv_basename || r.eval_id.slice(0, 8);
      const ts = r.evaluated_at ? r.evaluated_at.replace('T', ' ').slice(0, 16) : '';
      opt.textContent = `${label} \u2014 ${r.version || '?'} \u2014 ${r.device || '?'}(${formatProtocol(r.protocol)}) \u2014 n=${r.n_runs} \u2014 ${ts}`;
      sel.appendChild(opt);
    });
    reportsListLoaded = true;
  } catch (e) {
    console.error('Failed to load reports:', e);
  }
}

document.getElementById('report-selector')?.addEventListener('change', e => {
  const id = e.target.value;
  if (id) loadReport(id);
  else {
    document.getElementById('reports-empty').classList.remove('hidden');
    document.getElementById('reports-content').classList.add('hidden');
  }
});

async function loadReport(evalId) {
  try {
    const res = await fetch(`/api/reports/${evalId}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const r = await res.json();

    document.getElementById('reports-empty').classList.add('hidden');
    document.getElementById('reports-content').classList.remove('hidden');

    renderReportHero(r);
    renderReportAggregates(r.aggregates);
    renderReportCrashesChart(r.rows);
    renderReportRqChart(r.rq_level_distribution);
    renderReportTtfcChart(r.rows);
    renderReportTokensChart(r.rows);
    renderReportTable(r.rows);
  } catch (e) {
    console.error('Failed to load report:', e);
  }
}

function renderReportHero(r) {
  const cfg = r.config || {};
  const modelShort = (cfg.model || '').includes('/') ? cfg.model.split('/').pop() : (cfg.model || '\u2014');
  const cards = [
    { label: 'Report', value: esc(r.source_csv_basename || r.eval_id.slice(0, 12)), accent: 'muted' },
    { label: 'Runs', value: r.n_runs, accent: 'blue' },
    { label: 'Model', value: esc(modelShort), accent: 'orange' },
    { label: 'Version', value: esc(cfg.version || '\u2014'), accent: 'yellow' },
    { label: 'Device', value: esc(cfg.device || '\u2014'), accent: 'yellow' },
    { label: 'Protocol', value: esc(formatProtocol(cfg.protocol)), accent: 'yellow' },
    { label: 'Max Turns', value: cfg.max_turns ?? '\u2014', accent: 'muted' },
  ];
  document.getElementById('reports-hero').innerHTML =
    `<div class="hero-row">${cards.map(c => `
      <div class="hero-card accent-${c.accent}">
        <div class="card-label">${c.label}</div>
        <div class="card-value">${c.value}</div>
      </div>`).join('')}</div>`;
}

function renderReportAggregates(agg) {
  const fmt = (v, digits = 2) => v == null ? '\u2014' :
    (typeof v === 'number' ? v.toFixed(digits) : String(v));
  const stats = [
    { label: 'RQ Mean', a: agg.rq_mean_score, fmt: v => fmt(v, 2), accent: 'green' },
    { label: 'Total Crashes', a: agg.total_crashes, fmt: v => fmt(v, 1), accent: 'red' },
    { label: 'Unique Novel', a: agg.unique_novel, fmt: v => fmt(v, 1), accent: 'purple' },
    { label: 'Tests / Run', a: agg.total_tests, fmt: v => fmt(v, 1), accent: 'cyan' },
    { label: 'Session Time', a: agg.total_session_time_seconds, fmt: v => v == null ? '\u2014' : fmtTime(v), accent: 'muted' },
    { label: 'Tokens In', a: agg.total_input_tokens, fmt: v => v == null ? '\u2014' : fmtTokens(v), accent: 'blue' },
  ];
  document.getElementById('reports-aggregates').innerHTML =
    `<div class="hero-row">${stats.map(s => {
      const a = s.a || {};
      const meanV = a.mean != null ? s.fmt(a.mean) : '\u2014';
      const sub = a.n
        ? `min ${s.fmt(a.min)} \u00b7 max ${s.fmt(a.max)} \u00b7 \u03c3 ${s.fmt(a.stdev)}`
          + (a.n_na ? ` \u00b7 ${a.n_na} N/A` : '')
        : 'no data';
      return `
        <div class="hero-card accent-${s.accent}" style="min-width:140px">
          <div class="card-label">${s.label} (mean)</div>
          <div class="card-value">${meanV}</div>
          <div class="card-sub">${sub}</div>
        </div>`;
    }).join('')}</div>`;
}

function _runShort(runId) { return runId ? runId.slice(0, 8) : '?'; }

function renderReportCrashesChart(rows) {
  const div = document.getElementById('reports-crashes-chart');
  if (!rows.length) { noData(div); return; }
  const x = rows.map(r => _runShort(r.run_id));
  const traces = [
    { name: 'Publicly Known', y: rows.map(r => r.publicly_known_crashes || 0), marker: { color: C.muted } },
    { name: 'Non-Public',     y: rows.map(r => r.non_publicly_known_crashes || 0), marker: { color: C.orange } },
    { name: 'Fully Novel',    y: rows.map(r => r.fully_novel_crashes || 0), marker: { color: C.red } },
  ].map(t => ({ ...t, x, type: 'bar' }));
  Plotly.newPlot(div, traces, {
    ...PLT, barmode: 'stack', height: 280,
    xaxis: { ...PLT.xaxis, title: { text: 'Run', font: { size: 10 } } },
    yaxis: { ...PLT.yaxis, title: { text: 'Crashes', font: { size: 10 } } },
    legend: { orientation: 'h', y: -0.25 },
  }, CFG);
}

function renderReportRqChart(dist) {
  const div = document.getElementById('reports-rq-chart');
  const levels = ['L0', 'L1', 'L2', 'L3', 'L4', 'L5'];
  const counts = levels.map(l => dist[l] || 0);
  if (!counts.some(c => c > 0)) { noData(div); return; }
  Plotly.newPlot(div, [{
    x: levels, y: counts, type: 'bar',
    marker: { color: [C.muted, C.cyan, C.blue, C.green, C.purple, C.orange] },
    text: counts.map(String), textposition: 'auto',
  }], {
    ...PLT, height: 220,
    xaxis: { ...PLT.xaxis, title: { text: 'RQ Max Level', font: { size: 10 } } },
    yaxis: { ...PLT.yaxis, title: { text: 'Runs', font: { size: 10 } }, dtick: 1 },
  }, CFG);
}

function renderReportTtfcChart(rows) {
  const div = document.getElementById('reports-ttfc-chart');
  if (!rows.length) { noData(div); return; }
  const x = rows.map(r => _runShort(r.run_id));
  // Two traces so N/A runs are visually distinct from "0 seconds".
  const withCrash = rows.map(r => r.time_to_first_crash_seconds != null ? r.time_to_first_crash_seconds : null);
  const naMarker  = rows.map(r => r.time_to_first_crash_seconds == null ? 0 : null);
  Plotly.newPlot(div, [
    { x, y: withCrash, type: 'bar', name: 'Time to first crash (s)',
      marker: { color: C.blue }, text: withCrash.map(v => v != null ? v.toFixed(0) + 's' : ''), textposition: 'auto' },
    { x, y: naMarker, type: 'bar', name: 'No crash',
      marker: { color: C.muted, opacity: 0.4 },
      text: naMarker.map(v => v != null ? 'N/A' : ''), textposition: 'auto' },
  ], {
    ...PLT, barmode: 'overlay', height: 260,
    xaxis: { ...PLT.xaxis, title: { text: 'Run', font: { size: 10 } } },
    yaxis: { ...PLT.yaxis, title: { text: 'Seconds', font: { size: 10 } } },
    legend: { orientation: 'h', y: -0.25 },
  }, CFG);
}

function renderReportTokensChart(rows) {
  const div = document.getElementById('reports-tokens-chart');
  if (!rows.length) { noData(div); return; }
  const x = rows.map(r => _runShort(r.run_id));
  Plotly.newPlot(div, [
    { x, y: rows.map(r => r.total_input_tokens || 0), name: 'Input', type: 'bar', marker: { color: C.blue } },
    { x, y: rows.map(r => r.total_output_tokens || 0), name: 'Output', type: 'bar', marker: { color: C.purple } },
  ], {
    ...PLT, barmode: 'group', height: 260,
    xaxis: { ...PLT.xaxis, title: { text: 'Run', font: { size: 10 } } },
    yaxis: { ...PLT.yaxis, title: { text: 'Tokens', font: { size: 10 } } },
    legend: { orientation: 'h', y: -0.25 },
  }, CFG);
}

function renderReportTable(rows) {
  const container = document.getElementById('reports-table');
  if (!rows.length) {
    container.innerHTML = '<div class="no-data" style="min-height:60px">No rows</div>';
    return;
  }
  const fmt = (v, d = 2) => v == null ? '\u2014' : (typeof v === 'number' ? v.toFixed(d) : esc(String(v)));
  // Run-id cells deep-link to the existing run dashboard via the same
  // hash convention the run dropdown uses (see DOMContentLoaded handler).
  const rowsHtml = rows.map(r => `
    <tr>
      <td style="font-family:var(--mono);font-size:11px">
        <a href="#${esc(r.run_id || '')}" onclick="selectedRunId='${esc(r.run_id || '')}'; loadRun('${esc(r.run_id || '')}'); return false;">${esc(r.run_id || '')}</a>
      </td>
      <td style="font-family:var(--mono);font-size:10px">${esc(r.session_id || '')}</td>
      <td>${esc(r.rq_max_level || '')}</td>
      <td style="text-align:right;font-family:var(--mono)">${fmt(r.rq_mean_score, 2)}</td>
      <td style="text-align:right;font-family:var(--mono)">${r.total_crashes ?? 0}</td>
      <td style="text-align:right;font-family:var(--mono)">${r.unique_crashes ?? '\u2014'}</td>
      <td style="text-align:right;font-family:var(--mono)">${r.unique_novel ?? '\u2014'}</td>
      <td style="text-align:right;font-family:var(--mono)">${r.total_tests ?? '\u2014'}</td>
      <td style="text-align:right;font-family:var(--mono)">${r.time_to_first_crash_seconds != null ? r.time_to_first_crash_seconds.toFixed(1) + 's' : 'N/A'}</td>
      <td style="text-align:right;font-family:var(--mono)">${r.total_session_time_seconds != null ? fmtTime(r.total_session_time_seconds) : '\u2014'}</td>
    </tr>`).join('');
  container.innerHTML = `<table>
    <thead><tr>
      <th>Run</th><th>Session</th><th>RQ Lvl</th><th>RQ Mean</th>
      <th>Crashes</th><th>Unique</th><th>Novel</th>
      <th>Tests</th><th>Time\u21921st</th><th>Session</th>
    </tr></thead>
    <tbody>${rowsHtml}</tbody>
  </table>`;
}

/* ========== Helpers ========== */
function fmtTokens(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K';
  return String(n);
}

function noData(div) {
  if (div) div.innerHTML = '<div class="no-data">No data available</div>';
}

function trunc(s, n) { return s.length > n ? s.slice(0, n) + '\u2026' : s; }

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
