/* ===========================================================================
   EASM Dashboard — Frontend Application
   =========================================================================== */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const API = '/api';

// ---------------------------------------------------------------------------
// Auth — optional shared-secret header (matches DASHBOARD_TOKEN on the server).
// When the server has no token configured, /api/ never returns 401 and none of
// this engages. The token lives in sessionStorage (cleared when the tab closes).
// ---------------------------------------------------------------------------
const AUTH_HEADER = 'X-EASM-Token';
const AUTH_STORE_KEY = 'easm_token';

function getToken() { return sessionStorage.getItem(AUTH_STORE_KEY) || ''; }
function setToken(t) {
    if (t) sessionStorage.setItem(AUTH_STORE_KEY, t);
    else sessionStorage.removeItem(AUTH_STORE_KEY);
}
function promptToken(message) {
    const t = window.prompt(message || 'Enter the dashboard access token:', '');
    if (t !== null) setToken(t.trim());
    return getToken();
}

function _isApiUrl(input) {
    const s = (typeof input === 'string') ? input : (input && (input.href || input.url)) || '';
    return /^(https?:\/\/[^/]+)?\/api\//.test(s);
}
function _withToken(init) {
    const opts = { ...(init || {}) };
    const headers = new Headers(opts.headers || {});
    const tok = getToken();
    if (tok) headers.set(AUTH_HEADER, tok);
    opts.headers = headers;
    return opts;
}

// Wrap fetch so every same-origin /api/ request carries the token, and a single
// 401 re-prompts and retries. Non-API requests (static assets) pass through
// untouched. Must run before any fetch() call is made.
const _origFetch = window.fetch.bind(window);
let _authPrompting = false;
window.fetch = async function(input, init) {
    if (!_isApiUrl(input)) return _origFetch(input, init);
    let res = await _origFetch(input, _withToken(init));
    if (res.status === 401 && !_authPrompting) {
        _authPrompting = true;
        try {
            promptToken('Access denied. Enter the dashboard access token:');
        } finally {
            _authPrompting = false;
        }
        if (getToken()) res = await _origFetch(input, _withToken(init));
    }
    return res;
};

// Probe once at boot so first-time users are prompted immediately instead of
// seeing a wall of failed requests. Uses the raw fetch to avoid double-prompting.
async function ensureAuth() {
    for (let i = 0; i < 3; i++) {
        let res;
        try {
            res = await _origFetch('/api/scans/active', _withToken({}));
        } catch (_) {
            return; // network/server error — let the normal flow surface it
        }
        if (res.status !== 401) return; // authorized, or no token required
        promptToken(i === 0
            ? 'This dashboard requires an access token:'
            : 'Invalid token. Try again:');
        if (!getToken()) return; // user cancelled
    }
}

const SEVERITY_COLORS = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308',
    low: '#3b82f6', info: '#6b7280',
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const PIPELINE_STAGES = [
    { id: 'subfinder',   name: 'Passive Subdomains',     tool: 'subfinder' },
    { id: 'ct',          name: 'CT Log Enrichment',      tool: 'crt.sh' },
    { id: 'dns',         name: 'DNS Resolution',        tool: 'dnsx' },
    { id: 'asn',         name: 'ASN Enrichment',         tool: 'pyasn' },
    { id: 'rdns',        name: 'Reverse DNS',            tool: 'dnsx' },
    { id: 'cdn',         name: 'CDN/Cloud/WAF Check',    tool: 'cdncheck' },
    { id: 'ports',       name: 'Port Scanning',          tool: 'naabu' },
    { id: 'http',        name: 'HTTP Probing',           tool: 'httpx' },
    { id: 'waf',         name: 'WAF Detection',          tool: 'waf-detect' },
    { id: 'tls',         name: 'TLS Analysis',           tool: 'tlsx' },
    { id: 'fingerprint', name: 'Fingerprinting',         tool: 'nerva' },
    { id: 'nuclei',      name: 'Vulnerability Scan',     tool: 'nuclei' },
    { id: 'cloud_enum',  name: 'Cloud Enumeration',      tool: 'cloud_enum.py' },
    { id: 'aimap',       name: 'AI Agent Discovery',     tool: 'aimap' },
    { id: 'normalize',   name: 'Normalization',          tool: 'normalize.py', required: true },
    { id: 'load',        name: 'DuckDB Load',            tool: 'load_duckdb.py', required: true },
    { id: 'verify',      name: 'Takeover Verification',  tool: 'verify.py' },
    { id: 'scope',       name: 'Tenable Scope Routing',  tool: 'cmdb_scope_export.py' },
];

const GAP_LABELS = {
    shadow_it: 'Shadow IT', stale_ci: 'Stale CI',
    unmanaged: 'Unmanaged', orphan_cert: 'Orphan Cert',
};

// ---------------------------------------------------------------------------
// Port Dictionary
// ---------------------------------------------------------------------------
const PORT_DICT = {
    21:    { name: 'FTP',            category: 'file_transfer',  risk: 'high',     desc: 'File Transfer Protocol — cleartext credentials' },
    22:    { name: 'SSH',            category: 'remote_access',  risk: 'medium',   desc: 'Secure Shell remote access' },
    23:    { name: 'Telnet',         category: 'remote_access',  risk: 'critical', desc: 'Cleartext remote terminal — do not expose' },
    25:    { name: 'SMTP',           category: 'email',          risk: 'medium',   desc: 'Mail Transfer — open relay risk if public' },
    53:    { name: 'DNS',            category: 'infrastructure', risk: 'medium',   desc: 'Domain Name System' },
    80:    { name: 'HTTP',           category: 'web',            risk: 'low',      desc: 'Unencrypted web traffic' },
    81:    { name: 'HTTP-alt',       category: 'web',            risk: 'low',      desc: 'Alternate HTTP port' },
    110:   { name: 'POP3',           category: 'email',          risk: 'medium',   desc: 'Post Office Protocol v3 — often cleartext' },
    111:   { name: 'RPCbind',        category: 'infrastructure', risk: 'high',     desc: 'Remote Procedure Call portmapper' },
    143:   { name: 'IMAP',           category: 'email',          risk: 'medium',   desc: 'Internet Message Access Protocol' },
    389:   { name: 'LDAP',           category: 'directory',      risk: 'high',     desc: 'Directory service — exposure risk' },
    443:   { name: 'HTTPS',          category: 'web',            risk: 'info',     desc: 'Encrypted web traffic (TLS)' },
    445:   { name: 'SMB',            category: 'file_share',     risk: 'critical', desc: 'Windows file sharing — high exploit risk' },
    465:   { name: 'SMTPS',          category: 'email',          risk: 'low',      desc: 'SMTP over TLS' },
    514:   { name: 'Syslog',         category: 'management',     risk: 'medium',   desc: 'System log forwarding (UDP)' },
    587:   { name: 'SMTP-submit',    category: 'email',          risk: 'low',      desc: 'Mail submission with auth' },
    636:   { name: 'LDAPS',          category: 'directory',      risk: 'medium',   desc: 'LDAP over TLS' },
    993:   { name: 'IMAPS',          category: 'email',          risk: 'low',      desc: 'IMAP over TLS' },
    995:   { name: 'POP3S',          category: 'email',          risk: 'low',      desc: 'POP3 over TLS' },
    1433:  { name: 'MSSQL',          category: 'database',       risk: 'critical', desc: 'Microsoft SQL Server — do not expose publicly' },
    1521:  { name: 'Oracle DB',      category: 'database',       risk: 'critical', desc: 'Oracle Database listener' },
    2049:  { name: 'NFS',            category: 'file_share',     risk: 'high',     desc: 'Network File System — exposure risk' },
    2082:  { name: 'cPanel HTTP',    category: 'management',     risk: 'medium',   desc: 'cPanel hosting control panel' },
    2083:  { name: 'cPanel HTTPS',   category: 'management',     risk: 'medium',   desc: 'cPanel over TLS' },
    2086:  { name: 'WHM HTTP',       category: 'management',     risk: 'medium',   desc: 'WHM/cPanel admin' },
    2087:  { name: 'WHM HTTPS',      category: 'management',     risk: 'medium',   desc: 'WHM over TLS' },
    2181:  { name: 'ZooKeeper',      category: 'infrastructure', risk: 'high',     desc: 'Apache ZooKeeper coordination service' },
    3000:  { name: 'Dev/Grafana',    category: 'web',            risk: 'medium',   desc: 'Node.js dev or Grafana dashboard' },
    3306:  { name: 'MySQL',          category: 'database',       risk: 'critical', desc: 'MySQL/MariaDB — do not expose publicly' },
    3389:  { name: 'RDP',            category: 'remote_access',  risk: 'critical', desc: 'Windows Remote Desktop — high attack surface' },
    4443:  { name: 'HTTPS-alt',      category: 'web',            risk: 'low',      desc: 'Alternate HTTPS port' },
    4444:  { name: 'Metasploit',     category: 'suspicious',     risk: 'critical', desc: 'Common backdoor / Metasploit default' },
    5000:  { name: 'Dev/Docker',     category: 'web',            risk: 'medium',   desc: 'Flask dev server or Docker registry' },
    5001:  { name: 'Dev-alt',        category: 'web',            risk: 'medium',   desc: 'Alternate dev/API port' },
    5432:  { name: 'PostgreSQL',     category: 'database',       risk: 'critical', desc: 'PostgreSQL — do not expose publicly' },
    5601:  { name: 'Kibana',         category: 'monitoring',     risk: 'high',     desc: 'Elastic Kibana dashboard' },
    5900:  { name: 'VNC',            category: 'remote_access',  risk: 'critical', desc: 'Virtual Network Computing — desktop sharing' },
    6379:  { name: 'Redis',          category: 'cache',          risk: 'critical', desc: 'Redis in-memory store — unauthenticated by default' },
    6443:  { name: 'Kubernetes API', category: 'container',      risk: 'critical', desc: 'Kubernetes API server' },
    7001:  { name: 'WebLogic',       category: 'web',            risk: 'high',     desc: 'Oracle WebLogic admin port' },
    7002:  { name: 'WebLogic SSL',   category: 'web',            risk: 'high',     desc: 'Oracle WebLogic SSL' },
    8000:  { name: 'HTTP-dev',       category: 'web',            risk: 'medium',   desc: 'Common dev HTTP port' },
    8008:  { name: 'HTTP-alt',       category: 'web',            risk: 'medium',   desc: 'Alternate HTTP / Chromecast' },
    8080:  { name: 'HTTP-proxy',     category: 'web',            risk: 'medium',   desc: 'HTTP proxy or app server' },
    8081:  { name: 'HTTP-alt',       category: 'web',            risk: 'medium',   desc: 'Alternate HTTP port' },
    8090:  { name: 'Confluence',     category: 'web',            risk: 'medium',   desc: 'Atlassian Confluence default' },
    8443:  { name: 'HTTPS-alt',      category: 'web',            risk: 'low',      desc: 'Alternate HTTPS / admin panels' },
    8888:  { name: 'Jupyter',        category: 'monitoring',     risk: 'critical', desc: 'Jupyter Notebook — unauthenticated code exec risk' },
    9000:  { name: 'SonarQube',      category: 'monitoring',     risk: 'medium',   desc: 'SonarQube or PHP-FPM' },
    9001:  { name: 'Portainer',      category: 'container',      risk: 'high',     desc: 'Portainer Docker UI' },
    9090:  { name: 'Prometheus',     category: 'monitoring',     risk: 'high',     desc: 'Prometheus metrics — exposes internal data' },
    9092:  { name: 'Kafka',          category: 'message_queue',  risk: 'high',     desc: 'Apache Kafka broker' },
    9200:  { name: 'Elasticsearch',  category: 'database',       risk: 'critical', desc: 'Elasticsearch — unauthenticated by default in old versions' },
    9300:  { name: 'ES Cluster',     category: 'database',       risk: 'critical', desc: 'Elasticsearch cluster communication' },
    9443:  { name: 'HTTPS-alt',      category: 'web',            risk: 'low',      desc: 'Alternate HTTPS' },
    11211: { name: 'Memcached',      category: 'cache',          risk: 'critical', desc: 'Memcached — unauthenticated, amplification DDoS risk' },
    27017: { name: 'MongoDB',        category: 'database',       risk: 'critical', desc: 'MongoDB — historically exposed without auth' },
    27018: { name: 'MongoDB shard',  category: 'database',       risk: 'critical', desc: 'MongoDB shard server' },
    50000: { name: 'SAP',            category: 'management',     risk: 'high',     desc: 'SAP Message Server' },
};

const PORT_CATEGORY_COLORS = {
    web:            { bg: 'rgba(47,217,176,0.15)',   border: '#2FD9B0', text: '#5FE8C6' },
    database:       { bg: 'rgba(239,68,68,0.15)',   border: '#ef4444', text: '#fca5a5' },
    remote_access:  { bg: 'rgba(249,115,22,0.15)',  border: '#f97316', text: '#fdba74' },
    email:          { bg: 'rgba(234,179,8,0.15)',   border: '#eab308', text: '#fde047' },
    file_transfer:  { bg: 'rgba(249,115,22,0.15)',  border: '#f97316', text: '#fdba74' },
    file_share:     { bg: 'rgba(239,68,68,0.15)',   border: '#ef4444', text: '#fca5a5' },
    directory:      { bg: 'rgba(249,115,22,0.15)',  border: '#f97316', text: '#fdba74' },
    cache:          { bg: 'rgba(239,68,68,0.15)',   border: '#ef4444', text: '#fca5a5' },
    container:      { bg: 'rgba(139,92,246,0.15)',  border: '#8b5cf6', text: '#c4b5fd' },
    monitoring:     { bg: 'rgba(234,179,8,0.15)',   border: '#eab308', text: '#fde047' },
    management:     { bg: 'rgba(234,179,8,0.15)',   border: '#eab308', text: '#fde047' },
    infrastructure: { bg: 'rgba(100,116,139,0.15)', border: '#6E827A', text: '#93A69E' },
    message_queue:  { bg: 'rgba(249,115,22,0.15)',  border: '#f97316', text: '#fdba74' },
    suspicious:     { bg: 'rgba(239,68,68,0.25)',   border: '#ef4444', text: '#fca5a5' },
    default:        { bg: 'rgba(100,116,139,0.12)', border: '#54655E', text: '#93A69E' },
};

const PORT_RISK_BADGE = {
    critical: 'badge-critical',
    high:     'badge-high',
    medium:   'badge-medium',
    low:      'badge-low',
    info:     'badge-info',
};

function portInfo(port) {
    return PORT_DICT[port] || { name: `Port ${port}`, category: 'default', risk: 'info', desc: '' };
}

function portCategoryStyle(category) {
    return PORT_CATEGORY_COLORS[category] || PORT_CATEGORY_COLORS.default;
}

// Deep Field chart theme tokens
const CHART_INK = '#93A69E';
const CHART_INK_FAINT = '#667A72';
const CHART_GRID = 'rgba(31, 43, 38, 0.9)';
const CHART_SIGNAL = '#2FD9B0';
const CHART_PANEL = '#101613';

const CHART_DEFAULTS = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: { labels: { color: CHART_INK, font: { family: 'IBM Plex Mono', size: 11 }, boxWidth: 10, boxHeight: 10, padding: 12 } },
        tooltip: {
            backgroundColor: CHART_PANEL, titleColor: '#E4EDE9',
            bodyColor: '#C6D3CD', borderColor: '#2C3B34', borderWidth: 1,
            padding: 10, cornerRadius: 8,
            titleFont: { family: 'Space Grotesk', weight: '600' },
            bodyFont: { family: 'IBM Plex Mono' },
        },
    },
};

// ---------------------------------------------------------------------------
// Icons (inline SVG)
// ---------------------------------------------------------------------------
const ICONS = {
    overview: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
    assets: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>',
    findings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    tls: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    cmdb: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
    network: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    takeovers: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/><line x1="2" y1="2" x2="22" y2="22" stroke="#ef4444" stroke-width="2"/></svg>',
    newScan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>',
    play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="w-4 h-4"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
    archive: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-4 h-4"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>',
    restore: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-3.5 h-3.5"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-3.5 h-3.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
    clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-3.5 h-3.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    chevronUp: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="w-3 h-3 inline"><polyline points="18 15 12 9 6 15"/></svg>',
    chevronDown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="w-3 h-3 inline"><polyline points="6 9 12 15 18 9"/></svg>',
    chevronRight: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="w-4 h-4 inline"><polyline points="9 18 15 12 9 6"/></svg>',
    arrowLeft: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-4 h-4"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>',
    externalLink: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-3.5 h-3.5 inline"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-5 h-5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="w-4 h-4"><polyline points="20 6 9 17 4 12"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-10 h-10"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-4 h-4"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    filter: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-4 h-4"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>',
    server: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" class="w-12 h-12 text-slate-600"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>',
    services: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><rect x="5" y="5" width="14" height="14" rx="1"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="2" x2="9" y2="5"/><line x1="15" y1="2" x2="15" y2="5"/><line x1="9" y1="19" x2="9" y2="22"/><line x1="15" y1="19" x2="15" y2="22"/><line x1="2" y1="9" x2="5" y2="9"/><line x1="2" y1="15" x2="5" y2="15"/><line x1="19" y1="9" x2="22" y2="9"/><line x1="19" y1="15" x2="22" y2="15"/></svg>',
    eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-3.5 h-3.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-3.5 h-3.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
    bounty: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><circle cx="12" cy="8" r="6"/><path d="M15.477 12.89L17 22l-5-3-5 3 1.523-9.11"/></svg>',
    aimap: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="M12 2a4 4 0 0 1 4 4c0 1.95-1.4 3.58-3.25 3.93"/><path d="M12 2a4 4 0 0 0-4 4c0 1.95 1.4 3.58 3.25 3.93"/><circle cx="12" cy="12" r="2"/><path d="M12 14v4"/><path d="M8 18h8"/><path d="M9 22h6"/><circle cx="5" cy="12" r="1.5"/><circle cx="19" cy="12" r="1.5"/><line x1="6.5" y1="12" x2="10" y2="12"/><line x1="14" y1="12" x2="17.5" y2="12"/></svg>',
    livecheck: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>',
    tenable: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v4"/><path d="M12 11c-4 0-7 2-7 6"/><path d="M12 11c4 0 7 2 7 6"/></svg>',
    cloud: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>',
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let state = {
    page: 'overview',
    pageParams: {},
    loading: false,
    error: null,
    cache: {},
};
const charts = {};

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------
async function api(endpoint, params = {}) {
    const url = new URL(API + endpoint, window.location.origin);
    Object.entries(params).forEach(([k, v]) => {
        if (v !== '' && v !== null && v !== undefined) url.searchParams.set(k, v);
    });
    url.searchParams.set('_t', Date.now());
    const res = await fetch(url);
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || `API error ${res.status}`);
    }
    return res.json();
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
function navigateTo(page, params = {}) {
    let hash = `#/${page}`;
    if (params.id)  hash += `/${encodeURIComponent(params.id)}`;
    if (params.id2) hash += `/${encodeURIComponent(params.id2)}`;
    window.location.hash = hash;
}

function parseHash() {
    const hash = window.location.hash.slice(1) || '/overview';
    const parts = hash.split('/').filter(Boolean);
    return {
        page: parts[0] || 'overview',
        params: {
            id:  parts[1] ? decodeURIComponent(parts[1]) : null,
            id2: parts[2] ? decodeURIComponent(parts[2]) : null,
        },
    };
}

function initRouter() {
    const route = () => {
        const { page, params } = parseHash();
        state.page = page;
        state.pageParams = params;
        renderApp();
    };
    window.addEventListener('hashchange', route);
    route();
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
function esc(s) {
    if (s == null) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function fmt(n) {
    if (n == null) return '0';
    return Number(n).toLocaleString('en-US');
}

function fmtPct(n) {
    if (n == null) return '0%';
    return Number(n).toFixed(1) + '%';
}

function fmtDate(d) {
    if (!d) return '-';
    try {
        return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch { return String(d); }
}

function debounce(fn, ms = 300) {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

function severityBadge(sev) {
    return `<span class="badge badge-${esc(sev)}">${esc(sev)}</span>`;
}

function gapBadge(gap) {
    if (!gap) return '<span class="text-slate-500">-</span>';
    return `<span class="badge badge-${esc(gap)}">${esc(GAP_LABELS[gap] || gap)}</span>`;
}

function confidenceClass(val) {
    if (val == null) return 'text-slate-500';
    if (val >= 0.9) return 'text-green-400';
    if (val >= 0.7) return 'text-yellow-400';
    return 'text-orange-400';
}

function destroyCharts() {
    Object.keys(charts).forEach(k => { charts[k].destroy(); delete charts[k]; });
}

function createChart(canvasId, config) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    if (charts[canvasId]) charts[canvasId].destroy();
    const c = new Chart(ctx, config);
    charts[canvasId] = c;
    return c;
}

function animateCounter(el, target, duration = 800) {
    const start = 0;
    const startTime = performance.now();
    const step = (now) => {
        const progress = Math.min((now - startTime) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = fmt(Math.round(start + (target - start) * eased));
        if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------
function renderApp() {
    destroyCharts();
    const app = document.getElementById('app');
    app.innerHTML = `
        <aside id="sidebar" class="fixed left-0 top-0 bottom-0 w-60 bg-[#0B100E] border-r border-surface-border flex flex-col z-30">
            ${renderSidebar()}
        </aside>
        <main id="main" class="ml-60 flex-1 min-h-screen">
            <div id="page-content" class="p-6 max-w-[1600px] mx-auto page-enter">
                ${renderLoadingState()}
            </div>
        </main>
    `;
    renderCurrentPage();
}

function renderSidebar() {
    // Grouped by the recon workflow: Discover the surface, Analyze what's on it,
    // Respond to what matters.
    const groups = [
        { label: 'Field', links: [
            { id: 'overview', label: 'Overview', icon: ICONS.overview },
            { id: 'scans', label: 'New Scan', icon: ICONS.newScan },
        ]},
        { label: 'Discover', links: [
            { id: 'assets', label: 'Assets', icon: ICONS.assets },
            { id: 'network', label: 'Network', icon: ICONS.network },
            { id: 'services', label: 'Services', icon: ICONS.services },
            { id: 'cloud', label: 'Cloud Assets', icon: ICONS.cloud },
            { id: 'aimap', label: 'AI Agents', icon: ICONS.aimap },
        ]},
        { label: 'Analyze', links: [
            { id: 'findings', label: 'Findings', icon: ICONS.findings },
            { id: 'tls', label: 'TLS Health', icon: ICONS.tls },
            { id: 'cmdb', label: 'CMDB Gaps', icon: ICONS.cmdb },
        ]},
        { label: 'Respond', links: [
            { id: 'takeovers', label: 'Takeovers', icon: ICONS.takeovers },
            { id: 'bounty', label: 'Bug Bounty', icon: ICONS.bounty },
            { id: 'livecheck', label: 'Livecheck', icon: ICONS.livecheck },
            { id: 'tenable', label: 'Tenable Scope', icon: ICONS.tenable },
        ]},
    ];
    return `
        <div class="px-5 py-5 flex items-center gap-3 border-b border-surface-border">
            <div class="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                 style="background: radial-gradient(circle at 30% 30%, rgba(47,217,176,0.22), rgba(47,217,176,0.04)); border: 1px solid rgba(47,217,176,0.35); box-shadow: 0 0 18px rgba(47,217,176,0.12);">
                <svg viewBox="0 0 24 24" fill="none" stroke="#2FD9B0" stroke-width="1.75" style="width:1.15rem;height:1.15rem">
                    <circle cx="12" cy="12" r="9"/>
                    <line x1="12" y1="1" x2="12" y2="5"/>
                    <line x1="12" y1="19" x2="12" y2="23"/>
                    <line x1="1" y1="12" x2="5" y2="12"/>
                    <line x1="19" y1="12" x2="23" y2="12"/>
                    <circle cx="12" cy="12" r="2" fill="#2FD9B0" stroke="none"/>
                </svg>
            </div>
            <div>
                <div class="font-semibold text-sm text-white tracking-tight leading-none">EASM</div>
                <div class="text-[10px] text-slate-500 font-mono tracking-[0.18em] uppercase mt-1">Deep Field</div>
            </div>
        </div>
        <nav class="flex-1 px-3 py-3 overflow-y-auto">
            ${groups.map(g => `
                <div class="nav-group-label">${g.label}</div>
                ${g.links.map(l => `
                    <a href="#/${l.id}" class="sidebar-link ${state.page === l.id ? 'active' : ''}" data-page="${l.id}">
                        ${l.icon}
                        <span>${l.label}</span>
                    </a>
                `).join('')}
            `).join('')}
        </nav>
        <div class="px-4 py-4 border-t border-surface-border">
            <div class="flex items-center gap-2">
                <div class="pulse-dot"></div>
                <span class="text-xs text-slate-500 font-mono tracking-wide">Pipeline connected</span>
            </div>
        </div>
    `;
}

function renderLoadingState() {
    return `
        <div class="flex items-center justify-center py-32">
            <div class="flex flex-col items-center gap-3">
                <div class="w-8 h-8 border-2 border-accent/30 border-t-accent rounded-full animate-spin"></div>
                <span class="text-slate-500 text-sm">Loading data...</span>
            </div>
        </div>
    `;
}

function renderErrorState(msg) {
    return `
        <div class="flex items-center justify-center py-32">
            <div class="flex flex-col items-center gap-4 text-center">
                <div class="text-red-400">${ICONS.warning}</div>
                <div>
                    <p class="text-slate-300 font-medium">Something went wrong</p>
                    <p class="text-sm text-slate-500 mt-1 max-w-md">${esc(msg)}</p>
                </div>
                <button onclick="renderCurrentPage()" class="text-sm text-accent hover:text-accent-light transition-colors">
                    Try again
                </button>
            </div>
        </div>
    `;
}

function renderEmptyState(title, subtitle) {
    return `
        <div class="empty-state">
            ${ICONS.server}
            <p class="text-slate-400 font-medium">${esc(title)}</p>
            <p class="text-sm text-slate-600 mt-1">${esc(subtitle || '')}</p>
        </div>
    `;
}

// ---------------------------------------------------------------------------
// Page Router
// ---------------------------------------------------------------------------
async function renderCurrentPage() {
    const content = document.getElementById('page-content');
    if (!content) return;
    content.innerHTML = renderLoadingState();
    content.className = 'p-6 max-w-[1600px] mx-auto page-enter';

    try {
        switch (state.page) {
            case 'overview': await pageOverview(content); break;
            case 'scans': await pageScans(content); break;
            case 'assets': await pageAssets(content); break;
            case 'detail': await pageAssetDetail(content, state.pageParams.id); break;
            case 'findings': await pageFindings(content); break;
            case 'tls': await pageTLS(content); break;
            case 'cmdb': await pageCMDB(content); break;
            case 'network': await pageNetwork(content); break;
            case 'takeovers': await pageTakeovers(content); break;
            case 'services': await pageServices(content); break;
            case 'aimap': await pageAimap(content); break;
            case 'cloud': await pageCloud(content); break;
            case 'bounty': await pageBounty(content); break;
            case 'livecheck': await pageLivecheck(content); break;
            case 'tenable': await pageTenable(content); break;
            case 'archive': await pageArchive(content, state.pageParams.id); break;
            case 'compare': await pageCompare(content, state.pageParams.id, state.pageParams.id2); break;
            default: await pageOverview(content); break;
        }
    } catch (e) {
        content.innerHTML = renderErrorState(e.message);
    }
}

// ---------------------------------------------------------------------------
// Page: Overview (Executive Dashboard)
// ---------------------------------------------------------------------------
async function pageOverview(el) {
    const data = await api('/overview');
    const s = data.scan || {};
    const sev = data.severity_map || {};
    const tls = data.tls_health || {};
    const totalAssets = s.total_assets || 0;
    const shadowIt = s.shadow_it || 0;
    const coveragePct = totalAssets > 0 ? ((s.in_cmdb || 0) / totalAssets * 100) : 0;

    const aimap = data.aimap || {};
    const aimapTotal = aimap.total || 0;
    const cloud = data.cloud || {};
    const cloudTotal = cloud.total_endpoints || 0;

    el.innerHTML = `
        <div class="mb-5">
            <div class="eyebrow mb-2">Surface Readout${s.scan_id ? ' · Scan ' + esc(s.scan_id) : ''}</div>
            <h1 class="text-2xl font-semibold text-white tracking-tight">Attack Surface Overview</h1>
        </div>

        ${renderSurfaceReadout(data, sev)}

        <!-- KPI Cards -->
        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4 mb-6">
            ${kpiCard('Total Assets', totalAssets, 'Discovered FQDNs', 'cyan', 'total')}
            ${kpiCard('Web Assets', s.web_assets, 'HTTP/HTTPS services', 'blue', 'web')}
            ${kpiCard('Shadow IT', shadowIt, totalAssets ? fmtPct(shadowIt / totalAssets * 100) + ' of total' : '', 'red', 'shadow')}
            ${kpiCard('Findings', s.total_findings, (sev.critical || 0) + ' critical', 'orange', 'findings')}
            ${kpiCard('TLS Issues', tls.issues_total, (tls.expired || 0) + ' expired', 'yellow', 'tls')}
            ${kpiCard('CMDB Coverage', fmtPct(coveragePct), (s.in_cmdb || 0) + ' matched', 'green', 'coverage', true)}
            ${kpiCard('Services', s.total_services, (s.assets_with_services || 0) + ' hosts', 'purple', 'services')}
            ${aimapTotal > 0 ? kpiCard('AI Agents', aimapTotal, 'exposed endpoints', 'purple', 'aimap') : ''}
            ${cloudTotal > 0 ? kpiCard('Cloud', cloudTotal, (cloud.total_hosts || 0) + ' hosts', 'blue', 'cloud') : ''}
        </div>

        <!-- Charts Row 1 -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Findings by Severity</h3>
                <div class="chart-container" style="height: 240px;">
                    <canvas id="chart-severity"></canvas>
                </div>
            </div>
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">CMDB Coverage</h3>
                <div class="chart-container" style="height: 240px;">
                    <canvas id="chart-cmdb"></canvas>
                </div>
            </div>
        </div>

        <!-- Charts Row 2 -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Top Technologies</h3>
                <div class="chart-container" style="height: 280px;">
                    <canvas id="chart-tech"></canvas>
                </div>
            </div>
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Port Distribution</h3>
                <div class="chart-container" style="height: 280px;">
                    <canvas id="chart-ports"></canvas>
                </div>
            </div>
        </div>

        <!-- Charts Row 3 -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">CDN Distribution</h3>
                <div class="chart-container" style="height: 240px;">
                    <canvas id="chart-cdn"></canvas>
                </div>
            </div>
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">TLS Certificate Health</h3>
                <div class="chart-container" style="height: 240px;">
                    <canvas id="chart-tls-health"></canvas>
                </div>
            </div>
        </div>

        <!-- Top Software Inventory -->
        ${data.top_software && data.top_software.length ? `
            <div class="card p-5 mb-4">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold text-slate-300">Top Software</h3>
                    <a href="#/services" class="text-xs text-accent hover:text-accent-light transition-colors">
                        Full inventory ${ICONS.chevronRight}
                    </a>
                </div>
                <div class="overflow-x-auto">
                    <table class="data-table">
                        <thead><tr><th>Product</th><th>Vendor</th><th>Version</th><th>Hosts</th></tr></thead>
                        <tbody>
                            ${data.top_software.map(i => `
                                <tr>
                                    <td class="font-medium">${esc(i.product)}</td>
                                    <td class="text-slate-400">${esc(i.vendor || '-')}</td>
                                    <td class="font-mono text-xs text-slate-400">${esc(i.version || '-')}</td>
                                    <td><span class="font-bold text-white">${fmt(i.host_count)}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : ''}

        <!-- Critical Findings Table -->
        ${data.critical_findings && data.critical_findings.length ? `
            <div class="card p-5">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold text-slate-300">Critical & High Findings</h3>
                    <a href="#/findings" class="text-xs text-accent hover:text-accent-light transition-colors">
                        View all ${ICONS.chevronRight}
                    </a>
                </div>
                <div class="overflow-x-auto">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>FQDN</th>
                                <th>Finding</th>
                                <th>Template</th>
                                <th>Matched At</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.critical_findings.map(f => `
                                <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(f.fqdn)}'})">
                                    <td>${severityBadge(f.severity)}</td>
                                    <td class="font-mono text-xs text-accent">${esc(f.fqdn)}</td>
                                    <td>${esc(f.finding_name)}</td>
                                    <td class="text-slate-500 font-mono text-xs">${esc(f.template_id)}</td>
                                    <td class="text-slate-400 text-xs">${esc(f.matched_at)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : ''}
    `;

    // Animate counters
    requestAnimationFrame(() => {
        document.querySelectorAll('[data-counter]').forEach(el => {
            const raw = el.getAttribute('data-counter');
            const val = parseFloat(raw);
            if (!isNaN(val)) animateCounter(el, val);
        });
    });

    // Create charts
    initOverviewCharts(data);
}

function riskZone(score) {
    if (score >= 75) return 'Critical';
    if (score >= 50) return 'High';
    if (score >= 25) return 'Elevated';
    return 'Nominal';
}

function renderSurfaceReadout(data, sev) {
    const score = Math.max(0, Math.min(100, Number(data.risk_score) || 0));
    const color = riskGaugeColor(score);
    const zone = riskZone(score);
    const counts = SEVERITY_ORDER.map(k => ({ sev: k, count: sev[k] || 0 }));
    const totalFindings = counts.reduce((a, c) => a + c.count, 0);

    const spectrumSegments = totalFindings > 0
        ? counts.filter(c => c.count > 0).map(c =>
            `<span style="flex-grow:${c.count};background:${SEVERITY_COLORS[c.sev]};box-shadow:inset 0 0 6px rgba(0,0,0,0.25)" title="${capitalize(c.sev)}: ${c.count}"></span>`
          ).join('')
        : `<span style="flex-grow:1;background:var(--field-sunken)"></span>`;

    const legend = counts.map(c => `
        <div class="item">
            <span class="dot" style="background:${SEVERITY_COLORS[c.sev]}"></span>
            <span>${capitalize(c.sev)}</span>
            <span class="val">${fmt(c.count)}</span>
        </div>
    `).join('');

    return `
        <div class="readout reticle mb-6">
            <div class="grid grid-cols-1 lg:grid-cols-[300px_1px_1fr] gap-6 lg:gap-8 items-center">
                <!-- Risk meter -->
                <div>
                    <div class="flex items-baseline justify-between mb-3">
                        <span class="eyebrow" style="letter-spacing:0.18em">Composite Risk</span>
                        <span class="text-[0.66rem] font-mono uppercase tracking-widest px-2 py-0.5 rounded"
                              style="color:${color};background:${color}1f;border:1px solid ${color}44">${zone}</span>
                    </div>
                    <div class="flex items-end gap-3 mb-3">
                        <span class="kpi-value text-5xl leading-none" style="color:${color}">${score}</span>
                        <span class="text-slate-500 font-mono text-xs mb-1">/ 100</span>
                    </div>
                    <div class="tick-meter">
                        <div class="tick-meter-track">
                            <div class="tick-meter-fill" style="width:${score}%;background:${color};color:${color}"></div>
                            <div class="tick-meter-needle" style="left:calc(${score}% - 1px)"></div>
                        </div>
                        <div class="tick-meter-ticks">
                            <span>0</span><span>25</span><span>50</span><span>75</span><span>100</span>
                        </div>
                    </div>
                </div>

                <!-- Divider -->
                <div class="hidden lg:block self-stretch" style="background:var(--hairline)"></div>

                <!-- Severity return spectrum -->
                <div>
                    <div class="flex items-baseline justify-between mb-3">
                        <span class="eyebrow" style="letter-spacing:0.18em">Severity Returns</span>
                        <span class="font-mono text-xs text-slate-400">${fmt(totalFindings)} total</span>
                    </div>
                    <div class="spectrum">${spectrumSegments}</div>
                    <div class="spectrum-legend">${legend}</div>
                </div>
            </div>
        </div>
    `;
}

function kpiCard(title, value, subtitle, color, id, isPercent = false) {
    const displayVal = isPercent ? value : fmt(value);
    const counterVal = isPercent ? '' : `data-counter="${value || 0}"`;
    return `
        <div class="card kpi-card p-4" data-color="${color}">
            <div class="text-[0.62rem] font-mono text-slate-500 uppercase tracking-[0.14em] mb-2">${esc(title)}</div>
            <div class="kpi-value text-2xl mb-1" ${counterVal}>${isPercent ? esc(displayVal) : '0'}</div>
            <div class="text-xs text-slate-500">${esc(subtitle || '')}</div>
        </div>
    `;
}

function riskColor(score) {
    if (score >= 75) return 'text-red-400';
    if (score >= 50) return 'text-orange-400';
    if (score >= 25) return 'text-yellow-400';
    return 'text-green-400';
}

function riskGaugeColor(score) {
    if (score >= 75) return '#ef4444';
    if (score >= 50) return '#f97316';
    if (score >= 25) return '#eab308';
    return '#10b981';
}

function renderRiskGauge(score) {
    const radius = 60;
    const circumference = Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;
    const color = riskGaugeColor(score);
    return `
        <svg class="risk-gauge" viewBox="0 0 160 90" width="120" height="68">
            <path d="M 20 80 A 60 60 0 0 1 140 80" class="risk-gauge-track"/>
            <path d="M 20 80 A 60 60 0 0 1 140 80" class="risk-gauge-fill"
                  stroke="${color}"
                  stroke-dasharray="${circumference}"
                  stroke-dashoffset="${offset}"/>
        </svg>
    `;
}

function initOverviewCharts(data) {
    const sev = data.findings_by_severity || [];
    if (sev.length) {
        createChart('chart-severity', {
            type: 'doughnut',
            data: {
                labels: sev.map(s => capitalize(s.severity)),
                datasets: [{
                    data: sev.map(s => s.count),
                    backgroundColor: sev.map(s => SEVERITY_COLORS[s.severity] || '#6b7280'),
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                cutout: '65%',
                plugins: {
                    ...CHART_DEFAULTS.plugins,
                    legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
                },
            },
        });
    }

    const scan = data.scan || {};
    const inCmdb = scan.in_cmdb || 0;
    const shadowIt = scan.shadow_it || 0;
    const staleCi = scan.stale_ci || 0;
    const other = Math.max(0, (scan.not_in_cmdb || 0) - shadowIt);
    if (inCmdb || shadowIt || staleCi || other) {
        createChart('chart-cmdb', {
            type: 'doughnut',
            data: {
                labels: ['In CMDB', 'Shadow IT', 'Stale CI', 'Other Gaps'],
                datasets: [{
                    data: [inCmdb, shadowIt, staleCi, other],
                    backgroundColor: ['#10b981', '#ef4444', '#eab308', '#f97316'],
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                cutout: '65%',
                plugins: {
                    ...CHART_DEFAULTS.plugins,
                    legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
                },
            },
        });
    }

    const tech = data.top_technologies || [];
    if (tech.length) {
        createChart('chart-tech', {
            type: 'bar',
            data: {
                labels: tech.map(t => t.name),
                datasets: [{
                    data: tech.map(t => t.count),
                    backgroundColor: 'rgba(47, 217, 176, 0.6)',
                    borderColor: '#2FD9B0',
                    borderWidth: 1,
                    borderRadius: 4,
                    barThickness: 18,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                indexAxis: 'y',
                plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
                scales: {
                    x: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', font: { size: 10 } } },
                    y: { grid: { display: false }, ticks: { color: '#93A69E', font: { family: 'IBM Plex Mono', size: 11 } } },
                },
            },
        });
    }

    const ports = data.port_distribution || [];
    if (ports.length) {
        createChart('chart-ports', {
            type: 'bar',
            data: {
                labels: ports.map(p => ':' + p.port),
                datasets: [{
                    data: ports.map(p => p.count),
                    backgroundColor: 'rgba(59, 130, 246, 0.6)',
                    borderColor: '#3b82f6',
                    borderWidth: 1,
                    borderRadius: 4,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#93A69E', font: { family: 'IBM Plex Mono', size: 10 } } },
                    y: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', font: { size: 10 } } },
                },
            },
        });
    }

    const cdn = data.cdn_distribution || [];
    if (cdn.length) {
        const palette = ['#2FD9B0', '#3b82f6', '#8b5cf6', '#ec4899', '#f97316', '#10b981', '#eab308', '#6E827A'];
        createChart('chart-cdn', {
            type: 'doughnut',
            data: {
                labels: cdn.map(c => c.cdn),
                datasets: [{
                    data: cdn.map(c => c.count),
                    backgroundColor: cdn.map((_, i) => palette[i % palette.length]),
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                cutout: '55%',
                plugins: {
                    ...CHART_DEFAULTS.plugins,
                    legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
                },
            },
        });
    }

    const tls = data.tls_health || {};
    const healthy = tls.healthy || 0;
    const expired = tls.expired || 0;
    const selfSigned = tls.self_signed || 0;
    const expiring = tls.expiring_30d || 0;
    const mismatched = tls.mismatched || 0;
    if (healthy || expired || selfSigned || expiring || mismatched) {
        createChart('chart-tls-health', {
            type: 'doughnut',
            data: {
                labels: ['Healthy', 'Expired', 'Self-Signed', 'Expiring <30d', 'Mismatched'],
                datasets: [{
                    data: [healthy, expired, selfSigned, expiring, mismatched],
                    backgroundColor: ['#10b981', '#ef4444', '#f97316', '#eab308', '#8b5cf6'],
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                cutout: '65%',
                plugins: {
                    ...CHART_DEFAULTS.plugins,
                    legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
                },
            },
        });
    }
}

// ---------------------------------------------------------------------------
// Page: Assets
// ---------------------------------------------------------------------------
let assetState = { page: 1, search: '', sort: 'fqdn', order: 'asc', tag: '', gap_type: '', has_findings: '' };

async function pageAssets(el) {
    const data = await api('/assets', { ...assetState, limit: 50 });
    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Asset Explorer</h1>
                <p class="text-sm text-slate-500 mt-1">${fmt(data.total)} assets discovered</p>
            </div>
        </div>

        <!-- Filters -->
        <div class="flex flex-wrap items-center gap-3 mb-4">
            <div class="relative flex-1 min-w-[240px] max-w-md">
                <div class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">${ICONS.search}</div>
                <input type="text" id="asset-search" class="search-input" placeholder="Search by FQDN..."
                       value="${esc(assetState.search)}">
            </div>
            <select id="asset-filter-gap" class="search-input max-w-[160px] pl-3"
                    style="background-image: none;">
                <option value="">All Gap Types</option>
                <option value="shadow_it" ${assetState.gap_type === 'shadow_it' ? 'selected' : ''}>Shadow IT</option>
                <option value="stale_ci" ${assetState.gap_type === 'stale_ci' ? 'selected' : ''}>Stale CI</option>
                <option value="unmanaged" ${assetState.gap_type === 'unmanaged' ? 'selected' : ''}>Unmanaged</option>
            </select>
            <label class="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
                <input type="checkbox" id="asset-filter-findings" class="accent-cyan-500"
                       ${assetState.has_findings === 'true' ? 'checked' : ''}>
                Has findings
            </label>
        </div>

        <!-- Table -->
        <div class="card overflow-hidden">
            <div class="overflow-x-auto">
                <table class="data-table" id="assets-table">
                    <thead>
                        <tr>
                            ${assetTableHeader('fqdn', 'FQDN')}
                            ${assetTableHeader('port_count', 'Ports')}
                            ${assetTableHeader('web_entry_count', 'Web')}
                            ${assetTableHeader('finding_count', 'Findings')}
                            ${assetTableHeader('tls_cert_count', 'TLS')}
                            ${assetTableHeader('cdn', 'CDN')}
                            ${assetTableHeader('asn_org', 'ASN')}
                            ${assetTableHeader('gap_type', 'CMDB Gap')}
                        </tr>
                    </thead>
                    <tbody>
                        ${data.items.length ? data.items.map(a => `
                            <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(a.fqdn)}'})">
                                <td class="font-mono text-xs text-accent">${esc(a.fqdn)}</td>
                                <td>${a.port_count || 0}</td>
                                <td>${a.web_entry_count || 0}</td>
                                <td>${a.finding_count ? `<span class="text-orange-400 font-medium">${a.finding_count}</span>` : '<span class="text-slate-600">0</span>'}</td>
                                <td>${a.tls_cert_count || 0}</td>
                                <td class="text-slate-400 text-xs">${esc(a.cdn || '-')}</td>
                                <td class="text-slate-400 text-xs max-w-[160px] truncate">${esc(a.asn_org || '-')}</td>
                                <td>${gapBadge(a.gap_type)}</td>
                            </tr>
                        `).join('') : `<tr><td colspan="8">${renderEmptyState('No assets found', 'Try adjusting your filters')}</td></tr>`}
                    </tbody>
                </table>
            </div>
            ${data.pages > 1 ? renderPagination(data.page, data.pages, 'asset') : ''}
        </div>
    `;

    // Event listeners
    const searchInput = document.getElementById('asset-search');
    const debouncedSearch = debounce((v) => {
        assetState.search = v;
        assetState.page = 1;
        pageAssets(el);
    });
    searchInput.addEventListener('input', (e) => debouncedSearch(e.target.value));

    document.getElementById('asset-filter-gap').addEventListener('change', (e) => {
        assetState.gap_type = e.target.value;
        assetState.page = 1;
        pageAssets(el);
    });

    document.getElementById('asset-filter-findings').addEventListener('change', (e) => {
        assetState.has_findings = e.target.checked ? 'true' : '';
        assetState.page = 1;
        pageAssets(el);
    });
}

function assetTableHeader(col, label) {
    const active = assetState.sort === col;
    const icon = active ? (assetState.order === 'asc' ? ICONS.chevronUp : ICONS.chevronDown) : '';
    return `<th class="${active ? 'sorted' : ''}" onclick="sortAssets('${col}')">${label} ${icon}</th>`;
}

window.sortAssets = function(col) {
    if (assetState.sort === col) {
        assetState.order = assetState.order === 'asc' ? 'desc' : 'asc';
    } else {
        assetState.sort = col;
        assetState.order = 'asc';
    }
    assetState.page = 1;
    const el = document.getElementById('page-content');
    if (el) pageAssets(el);
};

window.assetPage = function(p) {
    assetState.page = p;
    const el = document.getElementById('page-content');
    if (el) pageAssets(el);
};

// ---------------------------------------------------------------------------
// Page: Asset Detail
// ---------------------------------------------------------------------------
async function pageAssetDetail(el, fqdn) {
    if (!fqdn) { navigateTo('assets'); return; }
    const asset = await api(`/assets/${encodeURIComponent(fqdn)}`);

    const dns = asset.dns || {};
    const net = asset.network || {};
    const asn = net.asn || {};
    const web = asset.web || [];
    const tls = asset.tls || [];
    const services = asset.services || [];
    const findings = asset.findings || [];
    const cmdb = asset.cmdb || {};
    const cloudData = asset.cloud || {};
    const cloudEndpoints = cloudData.endpoints || [];

    el.innerHTML = `
        <div class="mb-6">
            <button onclick="history.back()" class="flex items-center gap-2 text-sm text-slate-400 hover:text-accent transition-colors mb-3">
                ${ICONS.arrowLeft} Back
            </button>
            <div class="flex items-center gap-3">
                <h1 class="text-2xl font-bold text-white font-mono">${esc(fqdn)}</h1>
                ${(asset.tags || []).map(t => `<span class="badge badge-info">${esc(t)}</span>`).join('')}
                ${cmdb.gap_type ? gapBadge(cmdb.gap_type) : cmdb.in_cmdb ? '<span class="badge badge-low">In CMDB</span>' : ''}
            </div>
            <p class="text-sm text-slate-500 mt-1">
                Sources: ${(asset.source || []).join(', ')} &middot; Scan: ${esc(asset.scan_id)}
            </p>
        </div>

        <!-- Summary Cards -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="card p-4">
                <div class="text-xs text-slate-500 mb-1">IP Addresses</div>
                <div class="font-mono text-sm text-white">${(dns.a || []).join(', ') || '-'}</div>
            </div>
            <div class="card p-4">
                <div class="text-xs text-slate-500 mb-1">CDN / ASN</div>
                <div class="text-sm text-white">${esc(net.cdn || 'Direct')} &middot; ${esc(asn.org || 'N/A')}</div>
                ${net.waf ? `<div class="text-xs text-slate-500 mt-1">WAF: <span class="text-accent">${esc(net.waf.provider)}</span> ${fmtPct((net.waf.confidence || 0) * 100)}</div>` : ''}
            </div>
            <div class="card p-4">
                <div class="text-xs text-slate-500 mb-1">Open Ports</div>
                <div class="font-mono text-sm text-white">${(net.open_ports || []).map(p => p.port).join(', ') || 'None'}</div>
            </div>
            <div class="card p-4">
                <div class="text-xs text-slate-500 mb-1">CMDB Status</div>
                <div class="text-sm">${cmdb.in_cmdb ? `<span class="text-green-400">Matched</span> (${esc(cmdb.matched_ci)})` : '<span class="text-red-400">Not in CMDB</span>'}</div>
            </div>
        </div>

        <!-- DNS -->
        ${dns.cname_chain && dns.cname_chain.length ? `
            <div class="card p-4 mb-4">
                <h3 class="text-sm font-semibold text-slate-300 mb-2">CNAME Chain</h3>
                <div class="flex items-center gap-2 flex-wrap font-mono text-xs">
                    <span class="text-accent">${esc(fqdn)}</span>
                    ${dns.cname_chain.map(c => `<span class="text-slate-600">&rarr;</span> <span class="text-slate-300">${esc(c)}</span>`).join('')}
                </div>
            </div>
        ` : ''}

        <!-- Web Entries -->
        ${web.length ? `
            <div class="card p-5 mb-4">
                <h3 class="text-sm font-semibold text-slate-300 mb-3">Web Services (${web.length})</h3>
                <div class="space-y-3">
                    ${web.map(w => `
                        <div class="bg-[#0B100E] rounded-lg p-4 border border-surface-border">
                            <div class="flex items-center gap-3 mb-2">
                                <span class="font-mono text-xs text-accent">${esc(w.url)}</span>
                                <span class="badge ${(w.status_code >= 200 && w.status_code < 400) ? 'badge-low' : 'badge-high'}">${w.status_code}</span>
                            </div>
                            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                                <div><span class="text-slate-500">Title:</span> <span class="text-slate-300">${esc(w.title || '-')}</span></div>
                                <div><span class="text-slate-500">Server:</span> <span class="text-slate-300">${esc(w.server || '-')}</span></div>
                                <div><span class="text-slate-500">Tech:</span> <span class="text-slate-300">${(w.tech || []).map(t => t.name || t).join(', ') || '-'}</span></div>
                                <div><span class="text-slate-500">JARM:</span> <span class="text-slate-300 font-mono">${esc(w.jarm ? w.jarm.substring(0, 20) + '...' : '-')}</span></div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        ` : ''}

        <!-- TLS Certificates -->
        ${tls.length ? `
            <div class="card p-5 mb-4">
                <h3 class="text-sm font-semibold text-slate-300 mb-3">TLS Certificates (${tls.length})</h3>
                <div class="overflow-x-auto">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Issuer</th>
                                <th>Subject</th>
                                <th>Expires</th>
                                <th>Days Left</th>
                                <th>Issues</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${tls.map(t => {
                                const issues = [];
                                if (t.expired) issues.push('Expired');
                                if (t.self_signed) issues.push('Self-Signed');
                                if (t.mismatched) issues.push('Mismatched');
                                if (t.revoked) issues.push('Revoked');
                                return `
                                    <tr>
                                        <td class="font-mono text-xs">${t.port}</td>
                                        <td class="text-xs">${esc(t.issuer)}</td>
                                        <td class="text-xs">${esc(t.subject)}</td>
                                        <td class="text-xs">${fmtDate(t.not_after)}</td>
                                        <td>${t.days_to_expiry != null ? `<span class="${t.days_to_expiry < 30 ? 'text-yellow-400' : t.days_to_expiry < 0 ? 'text-red-400' : 'text-green-400'}">${t.days_to_expiry}d</span>` : '-'}</td>
                                        <td>${issues.length ? issues.map(i => `<span class="badge badge-high mr-1">${i}</span>`).join('') : '<span class="text-green-400 text-xs">OK</span>'}</td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : ''}

        <!-- Services / Fingerprints -->
        ${services.length ? `
            <div class="card p-5 mb-4">
                <h3 class="text-sm font-semibold text-slate-300 mb-3">Service Fingerprints (${services.length})</h3>
                <div class="space-y-3">
                    ${services.map(s => {
                        const fp = s.fingerprint || {};
                        const os = [fp.os_vendor, fp.os_product, fp.os_version].filter(Boolean).join(' ');
                        const hasFp = fp.product || fp.version || fp.cpe23 || os;
                        return `
                            <div class="bg-[#0B100E] rounded-lg p-4 border border-surface-border">
                                <div class="flex items-center gap-3 mb-2">
                                    <span class="badge badge-info">${esc(s.service || 'unknown')}</span>
                                    <span class="font-mono text-xs text-slate-400">
                                        port ${s.port}${s.protocol ? `/${s.protocol}` : ''}
                                    </span>
                                    ${s.status && s.status !== 'success' ? `<span class="text-xs text-slate-500">${esc(s.status)}</span>` : ''}
                                    ${fp.certainty != null ? `
                                        <span class="ml-auto text-xs font-medium ${confidenceClass(fp.certainty)}">
                                            ${Math.round(fp.certainty * 100)}% confidence
                                        </span>
                                    ` : ''}
                                </div>
                                ${hasFp ? `
                                    <div class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs mt-2">
                                        ${fp.product ? `
                                            <div>
                                                <span class="text-slate-500">Product:</span>
                                                <span class="text-slate-200 ml-1">${esc(fp.vendor ? fp.vendor + ' ' + fp.product : fp.product)}</span>
                                            </div>
                                        ` : ''}
                                        ${fp.version ? `
                                            <div>
                                                <span class="text-slate-500">Version:</span>
                                                <span class="font-mono text-slate-300 ml-1">${esc(fp.version)}</span>
                                            </div>
                                        ` : ''}
                                        ${fp.cpe23 ? `
                                            <div class="col-span-2">
                                                <span class="text-slate-500">CPE:</span>
                                                <span class="font-mono text-slate-400 ml-1 break-all">${esc(fp.cpe23)}</span>
                                            </div>
                                        ` : ''}
                                        ${os ? `
                                            <div>
                                                <span class="text-slate-500">OS:</span>
                                                <span class="text-slate-300 ml-1">${esc(os)}</span>
                                            </div>
                                        ` : ''}
                                        ${fp.source ? `
                                            <div>
                                                <span class="text-slate-500">Source:</span>
                                                <span class="text-slate-500 ml-1">${esc(fp.source)}</span>
                                            </div>
                                        ` : ''}
                                    </div>
                                ` : ''}
                                ${s.banner ? `
                                    <div class="mt-2">
                                        <span class="text-[10px] text-slate-500 uppercase tracking-wider">Banner</span>
                                        <code class="block text-slate-400 text-xs font-mono bg-[#070A09] rounded p-2 mt-1 overflow-x-auto whitespace-pre-wrap break-all">${esc(s.banner)}</code>
                                    </div>
                                ` : ''}
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        ` : ''}

        <!-- Cloud Endpoints -->
        ${cloudEndpoints.length ? `
            <div class="card p-5 mb-4">
                <h3 class="text-sm font-semibold text-slate-300 mb-3">Cloud Endpoints (${cloudEndpoints.length})</h3>
                <div class="overflow-x-auto">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Provider</th>
                                <th>Service</th>
                                <th>Risk</th>
                                <th>Resource</th>
                                <th>Hostname</th>
                                <th>Signals</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${cloudEndpoints.map(ce => `
                                <tr>
                                    <td>${typeof providerBadge === 'function' ? providerBadge(ce.provider) : esc(ce.provider)}</td>
                                    <td class="text-sm text-slate-300">${esc(ce.service_label || ce.service)}</td>
                                    <td>${severityBadge(ce.risk)}</td>
                                    <td class="font-mono text-xs text-slate-400">${esc(ce.resource_name || '-')}</td>
                                    <td class="font-mono text-xs text-slate-500">${esc(ce.hostname || '-')}</td>
                                    <td class="text-xs text-slate-500">${(ce.signals || []).map(s => esc(s)).join(', ') || '-'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : ''}

        <!-- Findings -->
        ${findings.length ? `
            <div class="card p-5 mb-4">
                <h3 class="text-sm font-semibold text-slate-300 mb-3">Findings (${findings.length})</h3>
                <div class="overflow-x-auto">
                    <table class="data-table">
                        <thead><tr><th>Severity</th><th>Name</th><th>Template</th><th>Source</th><th>Matched At</th></tr></thead>
                        <tbody>
                            ${findings.map(f => `
                                <tr>
                                    <td>${severityBadge(f.severity)}</td>
                                    <td>${esc(f.name)}</td>
                                    <td class="font-mono text-xs text-slate-400">${esc(f.template_id)}</td>
                                    <td>${esc(f.source)}</td>
                                    <td class="font-mono text-xs text-slate-400">${esc(f.matched_at)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : ''}
    `;
}

// ---------------------------------------------------------------------------
// Page: Findings
// ---------------------------------------------------------------------------
let findingState = { severity: '', source: '', search: '', tag: '' };

async function pageFindings(el) {
    const [data, tagData] = await Promise.all([
        api('/findings', findingState),
        api('/findings/tags'),
    ]);
    const items = data.items || [];
    const summary = data.summary || [];
    const tags = (tagData.tags || []).slice(0, 30);

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Vulnerability Findings</h1>
                <p class="text-sm text-slate-500 mt-1">${fmt(items.length)} findings loaded</p>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="flex flex-wrap gap-3 mb-5">
            ${summary.map(s => `
                <button onclick="filterFindings('severity', '${s.severity === findingState.severity ? '' : s.severity}')"
                        class="card px-4 py-2.5 flex items-center gap-2 transition-all ${s.severity === findingState.severity ? 'ring-1 ring-accent' : 'card-interactive'}">
                    ${severityBadge(s.severity)}
                    <span class="text-lg font-bold text-white">${fmt(s.count)}</span>
                </button>
            `).join('')}
        </div>

        <!-- Tag Filter Pills -->
        ${tags.length ? `
            <div class="flex flex-wrap gap-2 mb-4">
                <span class="text-xs text-slate-500 self-center mr-1">Tags:</span>
                ${tags.map(t => `
                    <button onclick="filterFindings('tag', '${t.tag === findingState.tag ? '' : esc(t.tag)}')"
                            class="px-2.5 py-1 rounded-full text-xs font-medium transition-all ${t.tag === findingState.tag
                                ? 'bg-accent text-white'
                                : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}">
                        ${esc(t.tag)} <span class="opacity-60">${t.count}</span>
                    </button>
                `).join('')}
            </div>
        ` : ''}

        <!-- Filters -->
        <div class="flex flex-wrap items-center gap-3 mb-4">
            <div class="relative flex-1 min-w-[240px] max-w-md">
                <div class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">${ICONS.search}</div>
                <input type="text" id="finding-search" class="search-input" placeholder="Search findings..."
                       value="${esc(findingState.search)}">
            </div>
        </div>

        <!-- Severity Chart -->
        ${summary.length ? `
            <div class="card p-5 mb-4">
                <div class="chart-container" style="height: 200px;">
                    <canvas id="chart-findings-bar"></canvas>
                </div>
            </div>
        ` : ''}

        <!-- Table -->
        <div class="card overflow-hidden">
            <div class="overflow-x-auto" style="max-height: 600px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>FQDN</th>
                            <th>Finding</th>
                            <th>Template ID</th>
                            <th>Tags</th>
                            <th>Source</th>
                            <th>Matched At</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${items.length ? items.map(f => {
                            const fTags = (f.tags || []).filter(Boolean);
                            return `
                            <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(f.fqdn)}'})">
                                <td>${severityBadge(f.severity)}</td>
                                <td class="font-mono text-xs text-accent">${esc(f.fqdn)}</td>
                                <td>${esc(f.finding_name)}</td>
                                <td class="font-mono text-xs text-slate-500">${esc(f.template_id)}</td>
                                <td class="text-xs">${fTags.length ? fTags.map(t => `<span class="inline-block bg-slate-800 text-slate-300 rounded px-1.5 py-0.5 mr-1 mb-0.5">${esc(t)}</span>`).join('') : '<span class="text-slate-600">-</span>'}</td>
                                <td class="text-xs text-slate-400">${esc(f.finding_source)}</td>
                                <td class="text-xs text-slate-400 max-w-[200px] truncate">${esc(f.matched_at)}</td>
                            </tr>`;
                        }).join('') : `<tr><td colspan="7">${renderEmptyState('No findings', 'Adjust filters or run the pipeline')}</td></tr>`}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    // Search
    const searchInput = document.getElementById('finding-search');
    const debouncedSearch = debounce((v) => {
        findingState.search = v;
        pageFindings(el);
    });
    searchInput.addEventListener('input', (e) => debouncedSearch(e.target.value));

    // Bar chart
    if (summary.length) {
        createChart('chart-findings-bar', {
            type: 'bar',
            data: {
                labels: summary.map(s => capitalize(s.severity)),
                datasets: [{
                    data: summary.map(s => s.count),
                    backgroundColor: summary.map(s => SEVERITY_COLORS[s.severity] || '#6b7280'),
                    borderRadius: 6,
                    barThickness: 40,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#93A69E', font: { weight: '600' } } },
                    y: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A' } },
                },
            },
        });
    }
}

window.filterFindings = function(key, val) {
    findingState[key] = val;
    const el = document.getElementById('page-content');
    if (el) pageFindings(el);
};

// ---------------------------------------------------------------------------
// Page: TLS Health
// ---------------------------------------------------------------------------
async function pageTLS(el) {
    const data = await api('/tls');
    const items = data.items || [];
    const summary = data.summary || {};

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">TLS Certificate Health</h1>
                <p class="text-sm text-slate-500 mt-1">${fmt(summary.total || items.length)} certificates with issues</p>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
            ${kpiCard('Total Issues', summary.total, '', 'red', 'tls-total')}
            ${kpiCard('Expired', summary.expired, 'Certificates', 'red', 'tls-expired')}
            ${kpiCard('Self-Signed', summary.self_signed, 'Certificates', 'orange', 'tls-ss')}
            ${kpiCard('Expiring <30d', summary.expiring_30d, 'Certificates', 'yellow', 'tls-exp')}
            ${kpiCard('Mismatched', summary.mismatched, 'Subject mismatch', 'purple', 'tls-mm')}
            ${kpiCard('Untrusted', (summary.untrusted || 0) + (summary.revoked || 0), 'Revoked or untrusted', 'red', 'tls-unt')}
        </div>

        <!-- Chart -->
        <div class="card p-5 mb-4">
            <div class="chart-container" style="height: 240px;">
                <canvas id="chart-tls-detail"></canvas>
            </div>
        </div>

        <!-- Table -->
        <div class="card overflow-hidden">
            <div class="overflow-x-auto" style="max-height: 600px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>FQDN</th>
                            <th>Port</th>
                            <th>Issuer</th>
                            <th>Subject</th>
                            <th>Expires</th>
                            <th>Days Left</th>
                            <th>Issues</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${items.length ? items.map(t => {
                            const issues = [];
                            if (t.expired) issues.push('Expired');
                            if (t.self_signed) issues.push('Self-Signed');
                            if (t.mismatched) issues.push('Mismatched');
                            if (t.revoked) issues.push('Revoked');
                            if (t.untrusted) issues.push('Untrusted');
                            if (!issues.length && t.days_to_expiry != null && t.days_to_expiry < 30) issues.push('Expiring');
                            return `
                                <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(t.fqdn)}'})">
                                    <td class="font-mono text-xs text-accent">${esc(t.fqdn)}</td>
                                    <td class="font-mono text-xs">${t.port}</td>
                                    <td class="text-xs max-w-[200px] truncate">${esc(t.issuer)}</td>
                                    <td class="text-xs max-w-[160px] truncate">${esc(t.subject)}</td>
                                    <td class="text-xs">${fmtDate(t.not_after)}</td>
                                    <td class="${t.days_to_expiry < 0 ? 'text-red-400' : t.days_to_expiry < 30 ? 'text-yellow-400' : 'text-slate-400'} font-medium">${t.days_to_expiry != null ? t.days_to_expiry + 'd' : '-'}</td>
                                    <td>${issues.map(i => `<span class="badge badge-high mr-1">${i}</span>`).join('')}</td>
                                </tr>
                            `;
                        }).join('') : `<tr><td colspan="7">${renderEmptyState('No TLS issues found', 'All certificates are healthy')}</td></tr>`}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    // Animate counters
    requestAnimationFrame(() => {
        document.querySelectorAll('[data-counter]').forEach(el => {
            const val = parseFloat(el.getAttribute('data-counter'));
            if (!isNaN(val)) animateCounter(el, val);
        });
    });

    // Chart
    const categories = ['Expired', 'Self-Signed', 'Expiring <30d', 'Mismatched', 'Revoked', 'Untrusted'];
    const values = [summary.expired || 0, summary.self_signed || 0, summary.expiring_30d || 0, summary.mismatched || 0, summary.revoked || 0, summary.untrusted || 0];
    if (values.some(v => v > 0)) {
        createChart('chart-tls-detail', {
            type: 'bar',
            data: {
                labels: categories,
                datasets: [{
                    data: values,
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#8b5cf6', '#ec4899', '#6E827A'],
                    borderRadius: 6,
                    barThickness: 36,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#93A69E', font: { weight: '500' } } },
                    y: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', precision: 0 } },
                },
            },
        });
    }
}

// ---------------------------------------------------------------------------
// Page: CMDB Gaps
// ---------------------------------------------------------------------------
async function pageCMDB(el) {
    const data = await api('/cmdb', { gap_type: cmdbFilter });
    const items = data.items || [];
    const summary = data.summary || [];
    const cov = data.coverage || {};

    const total = cov.total || 0;
    const inCmdb = cov.in_cmdb || 0;
    const covPct = total > 0 ? (inCmdb / total * 100) : 0;

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">CMDB Gap Analysis</h1>
                <p class="text-sm text-slate-500 mt-1">Asset coverage and compliance tracking</p>
            </div>
        </div>

        <!-- KPIs -->
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
            ${kpiCard('Coverage', fmtPct(covPct), `${fmt(inCmdb)} of ${fmt(total)} assets`, 'green', 'cmdb-cov', true)}
            ${kpiCard('Not in CMDB', cov.not_in_cmdb, 'Unmatched assets', 'red', 'cmdb-notincmdb')}
            ${kpiCard('Shadow IT', cov.shadow_it, 'Live assets outside CMDB', 'red', 'cmdb-shadow')}
            ${kpiCard('Stale CI', cov.stale_ci, 'CMDB entries not found', 'yellow', 'cmdb-stale')}
            ${kpiCard('Total Assets', total, 'Across all sources', 'cyan', 'cmdb-total')}
        </div>

        <!-- Charts -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Gap Type Distribution</h3>
                <div class="chart-container" style="height: 240px;">
                    <canvas id="chart-gap-types"></canvas>
                </div>
            </div>
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Coverage Breakdown</h3>
                <div class="chart-container" style="height: 240px;">
                    <canvas id="chart-cmdb-cov"></canvas>
                </div>
            </div>
        </div>

        <!-- Category Definitions -->
        <div class="card p-5 mb-4">
            <h3 class="text-sm font-semibold text-slate-300 mb-4">Category Definitions &amp; Detection Logic</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div class="flex gap-3">
                    <div class="shrink-0 mt-0.5"><span class="badge badge-shadow_it">Shadow IT</span></div>
                    <div>
                        <p class="text-xs text-slate-300 font-medium mb-1">Undiscovered live asset</p>
                        <p class="text-xs text-slate-500 leading-relaxed">Asset is <span class="text-slate-400 font-medium">not registered in CMDB</span> but was actively discovered — it responds on HTTP/S or exposes open ports. This represents real attack surface that your change-management process has never captured.</p>
                        <p class="text-xs text-slate-600 mt-1.5 font-mono">in_cmdb = false AND (has_web OR port_count &gt; 0)</p>
                    </div>
                </div>
                <div class="flex gap-3">
                    <div class="shrink-0 mt-0.5"><span class="badge badge-stale_ci">Stale CI</span></div>
                    <div>
                        <p class="text-xs text-slate-300 font-medium mb-1">CMDB entry no longer reachable</p>
                        <p class="text-xs text-slate-500 leading-relaxed">Asset <span class="text-slate-400 font-medium">exists in CMDB</span> but was not found during active scanning — no DNS record, no IP, no certificate match. The CI may represent a decommissioned host, a migration artefact, or an entry never cleaned up.</p>
                        <p class="text-xs text-slate-600 mt-1.5 font-mono">in_cmdb = true AND fqdn NOT IN discovered_assets</p>
                    </div>
                </div>
                <div class="flex gap-3">
                    <div class="shrink-0 mt-0.5"><span class="badge badge-unmanaged">Unmanaged</span></div>
                    <div>
                        <p class="text-xs text-slate-300 font-medium mb-1">DNS-only presence, no services</p>
                        <p class="text-xs text-slate-500 leading-relaxed">Asset is <span class="text-slate-400 font-medium">not in CMDB</span> and resolves in DNS but exposes no detectable web surface or open ports. Lower immediate risk than Shadow IT, but still untracked infrastructure that may activate at any time.</p>
                        <p class="text-xs text-slate-600 mt-1.5 font-mono">in_cmdb = false AND dns.a != null AND NOT has_web AND port_count = 0</p>
                    </div>
                </div>
                <div class="flex gap-3">
                    <div class="shrink-0 mt-0.5"><span class="badge badge-orphan_cert">Orphan Cert</span></div>
                    <div>
                        <p class="text-xs text-slate-300 font-medium mb-1">Certificate with no DNS backing</p>
                        <p class="text-xs text-slate-500 leading-relaxed">A TLS certificate references this hostname (via CT logs or SAN enumeration), but no DNS record exists and no services were detected. Often indicates <span class="text-slate-400 font-medium">forgotten sub-domains</span>, expired certificates, or test/staging artefacts left in issuance logs.</p>
                        <p class="text-xs text-slate-600 mt-1.5 font-mono">in_cmdb = false AND has_cert = true AND dns.a = null</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Filter Tabs -->
        <div class="tab-bar">
            <button class="tab-btn ${!cmdbFilter ? 'active' : ''}" onclick="filterCmdb('')">All Gaps (${items.length})</button>
            ${summary.map(s => `
                <button class="tab-btn ${cmdbFilter === s.gap_type ? 'active' : ''}" onclick="filterCmdb('${s.gap_type}')">
                    ${esc(GAP_LABELS[s.gap_type] || s.gap_type)} (${s.count})
                </button>
            `).join('')}
        </div>

        <!-- Table -->
        <div class="card overflow-hidden">
            <div class="overflow-x-auto" style="max-height: 600px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>FQDN</th>
                            <th>Gap Type</th>
                            <th>IPs</th>
                            <th>CDN</th>
                            <th>Has Web</th>
                            <th>Ports</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${items.length ? items.map(g => `
                            <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(g.fqdn)}'})">
                                <td class="font-mono text-xs text-accent">${esc(g.fqdn)}</td>
                                <td>${gapBadge(g.gap_type)}</td>
                                <td class="font-mono text-xs text-slate-400">${(g.ips || []).slice(0, 2).join(', ') || '-'}</td>
                                <td class="text-xs text-slate-400">${esc(g.cdn || '-')}</td>
                                <td>${g.has_web ? '<span class="text-green-400">Yes</span>' : '<span class="text-slate-600">No</span>'}</td>
                                <td>${g.port_count || 0}</td>
                            </tr>
                        `).join('') : `<tr><td colspan="6">${renderEmptyState('No CMDB gaps', 'All assets are accounted for')}</td></tr>`}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    // Animate counters
    requestAnimationFrame(() => {
        document.querySelectorAll('[data-counter]').forEach(el => {
            const val = parseFloat(el.getAttribute('data-counter'));
            if (!isNaN(val)) animateCounter(el, val);
        });
    });

    // Charts
    if (summary.length) {
        const gapColors = { shadow_it: '#ef4444', stale_ci: '#eab308', unmanaged: '#f97316', orphan_cert: '#6b7280' };
        createChart('chart-gap-types', {
            type: 'doughnut',
            data: {
                labels: summary.map(s => GAP_LABELS[s.gap_type] || s.gap_type),
                datasets: [{
                    data: summary.map(s => s.count),
                    backgroundColor: summary.map(s => gapColors[s.gap_type] || '#6b7280'),
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: { ...CHART_DEFAULTS, cutout: '60%', plugins: { ...CHART_DEFAULTS.plugins, legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' } } },
        });
    }

    createChart('chart-cmdb-cov', {
        type: 'doughnut',
        data: {
            labels: ['In CMDB', 'Not in CMDB'],
            datasets: [{
                data: [inCmdb, cov.not_in_cmdb || 0],
                backgroundColor: ['#10b981', '#ef4444'],
                borderWidth: 0,
                hoverOffset: 6,
            }],
        },
        options: { ...CHART_DEFAULTS, cutout: '60%', plugins: { ...CHART_DEFAULTS.plugins, legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' } } },
    });
}

let cmdbFilter = '';
window.filterCmdb = function(gap) {
    cmdbFilter = gap;
    const el = document.getElementById('page-content');
    if (el) pageCMDB(el);
};

// ---------------------------------------------------------------------------
// Page: Network
// ---------------------------------------------------------------------------
let networkTab = 'ports';
let networkPortFilter = null;   // selected port number for heatmap filtering
let _portsData = null;          // cached heatmap + unfiltered details
let _portDetailCache = {};      // per-port detail cache

async function pageNetwork(el) {
    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Network Intelligence</h1>
                <p class="text-sm text-slate-500 mt-1">Ports, technologies, CDN and hosting analysis</p>
            </div>
        </div>
        <div class="tab-bar">
            <button class="tab-btn ${networkTab === 'ports' ? 'active' : ''}" onclick="switchNetworkTab('ports')">Port Distribution</button>
            <button class="tab-btn ${networkTab === 'tech' ? 'active' : ''}" onclick="switchNetworkTab('tech')">Tech Stack</button>
            <button class="tab-btn ${networkTab === 'cdn' ? 'active' : ''}" onclick="switchNetworkTab('cdn')">CDN Providers</button>
            <button class="tab-btn ${networkTab === 'asn' ? 'active' : ''}" onclick="switchNetworkTab('asn')">ASN / Hosting</button>
        </div>
        <div id="network-content">${renderLoadingState()}</div>
    `;

    await renderNetworkTab();
}

async function renderNetworkTab() {
    const container = document.getElementById('network-content');
    if (!container) return;
    container.innerHTML = renderLoadingState();

    try {
        switch (networkTab) {
            case 'ports': await renderPortsTab(container); break;
            case 'tech': await renderTechTab(container); break;
            case 'cdn': await renderCDNTab(container); break;
            case 'asn': await renderASNTab(container); break;
        }
    } catch (e) {
        container.innerHTML = renderErrorState(e.message);
    }
}

async function renderPortsTab(el) {
    if (!_portsData) {
        _portsData = await api('/network/ports');
    }
    const heatmap = _portsData.heatmap || [];
    const allDetails = _portsData.details || [];
    const maxCount = heatmap.length ? Math.max(...heatmap.map(h => h.count)) : 1;

    let filtered;
    if (networkPortFilter !== null) {
        if (!_portDetailCache[networkPortFilter]) {
            console.log('[renderPortsTab] fetching details for port:', networkPortFilter);
            const resp = await api('/network/ports', { port: networkPortFilter });
            console.log('[renderPortsTab] got', resp.details?.length, 'rows, ports:', [...new Set(resp.details?.map(d => d.port))]);
            _portDetailCache[networkPortFilter] = resp.details || [];
        }
        filtered = _portDetailCache[networkPortFilter];
    } else {
        filtered = allDetails;
    }
    console.log('[renderPortsTab] networkPortFilter:', networkPortFilter, 'filtered.length:', filtered.length);

    const activePort = networkPortFilter !== null ? portInfo(networkPortFilter) : null;

    el.innerHTML = `
        <!-- Port Frequency Chart -->
        <div class="card p-5 mb-4">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-sm font-semibold text-slate-300">Port Frequency</h3>
                <span class="text-xs text-slate-500">Click a bar or heatmap tile to filter assets</span>
            </div>
            <div class="chart-container" style="height: 280px;">
                <canvas id="chart-port-freq"></canvas>
            </div>
        </div>

        <!-- Interactive Heatmap -->
        <div class="card p-5 mb-4">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-sm font-semibold text-slate-300">Port Heatmap</h3>
                ${networkPortFilter !== null ? `
                    <button onclick="filterByPort(null)" class="flex items-center gap-1.5 text-xs text-accent hover:text-accent-light transition-colors">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="w-3.5 h-3.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        Clear filter
                    </button>
                ` : ''}
            </div>
            <div class="flex flex-wrap gap-2" id="port-heatmap">
                ${heatmap.map(h => {
                    const info = portInfo(h.port);
                    const cat = portCategoryStyle(info.category);
                    const isSelected = networkPortFilter === h.port;
                    const isOther = networkPortFilter !== null && !isSelected;
                    return `
                        <button
                            onclick="filterByPort(${isSelected ? null : h.port})"
                            class="port-tile ${isSelected ? 'port-tile-selected' : ''} ${isOther ? 'port-tile-dim' : ''}"
                            style="--tile-bg:${cat.bg}; --tile-border:${cat.border}; --tile-text:${cat.text};"
                            title="${esc(info.name)} — ${esc(info.desc)}\n${h.count} assets"
                        >
                            <div class="font-mono text-xs font-bold text-white">:${h.port}</div>
                            <div class="text-[10px] mt-0.5" style="color:${cat.text}">${esc(info.name)}</div>
                            <div class="text-[10px] text-slate-400 mt-0.5">${h.count}</div>
                        </button>
                    `;
                }).join('')}
            </div>
        </div>

        <!-- Port Context Banner (shown when port is selected) -->
        ${activePort ? `
            <div class="port-context-banner mb-4" id="port-context">
                <div class="flex items-start gap-4">
                    <div class="shrink-0">
                        <div class="font-mono text-2xl font-bold text-white">:${networkPortFilter}</div>
                        <div class="text-sm font-semibold mt-0.5" style="color:${portCategoryStyle(activePort.category).text}">${esc(activePort.name)}</div>
                    </div>
                    <div class="flex-1">
                        <p class="text-sm text-slate-300 mb-2">${esc(activePort.desc)}</p>
                        <div class="flex items-center gap-3">
                            <span class="badge ${PORT_RISK_BADGE[activePort.risk] || 'badge-info'}">${esc(activePort.risk)} risk</span>
                            <span class="text-xs text-slate-500 capitalize">${esc(activePort.category.replace('_', ' '))}</span>
                            <span class="text-xs text-slate-400">${filtered.length} asset${filtered.length !== 1 ? 's' : ''} on this port</span>
                        </div>
                    </div>
                </div>
            </div>
        ` : ''}

        <!-- Asset Details Table -->
        ${networkPortFilter !== null ? `
        <div class="card overflow-hidden">
            <div class="flex items-center justify-between px-4 py-3 border-b border-surface-border">
                <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Assets on port :${networkPortFilter} (${filtered.length})
                </span>
                <span class="text-xs text-slate-500">Click a row to inspect asset</span>
            </div>
            <div class="overflow-x-auto" style="max-height: 480px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>FQDN</th>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Protocol</th>
                            <th>CDN</th>
                            <th>ASN</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${filtered.length ? filtered.map(d => {
                            const info = portInfo(d.port);
                            const cat = portCategoryStyle(info.category);
                            return `
                                <tr class="clickable" onclick="openAssetPanel('${esc(d.fqdn)}')">
                                    <td class="font-mono text-xs text-accent">${esc(d.fqdn)}</td>
                                    <td>
                                        <span class="font-mono text-xs px-2 py-0.5 rounded"
                                              style="background:${cat.bg}; color:${cat.text}; border:1px solid ${cat.border}40">
                                            :${d.port}
                                        </span>
                                    </td>
                                    <td class="text-xs" style="color:${cat.text}">${esc(info.name)}</td>
                                    <td class="text-xs text-slate-400">${esc(d.protocol || 'tcp')}</td>
                                    <td class="text-xs text-slate-400">${esc(d.cdn || '—')}</td>
                                    <td class="text-xs text-slate-400 max-w-[200px] truncate">${esc(d.asn_org || '—')}</td>
                                </tr>
                            `;
                        }).join('') : `
                            <tr><td colspan="6">${renderEmptyState('No assets on port :' + networkPortFilter, 'Try a different port')}</td></tr>
                        `}
                    </tbody>
                </table>
            </div>
        </div>
        ` : `
        <div class="card p-8 text-center">
            <div class="text-slate-500 mb-2">
                ${ICONS.network}
            </div>
            <p class="text-sm text-slate-400">Select a port from the heatmap or chart above to view all assets</p>
        </div>
        `}
    `;

    // Build chart — bars clickable to set port filter
    if (heatmap.length) {
        const chartColors = heatmap.map(h => {
            const info = portInfo(h.port);
            const cat = portCategoryStyle(info.category);
            if (networkPortFilter === null) return cat.border;
            return networkPortFilter === h.port ? cat.border : cat.border + '40';
        });

        const c = createChart('chart-port-freq', {
            type: 'bar',
            data: {
                labels: heatmap.map(h => ':' + h.port),
                datasets: [{
                    data: heatmap.map(h => h.count),
                    backgroundColor: chartColors.map(c => c + '99'),
                    borderColor: chartColors,
                    borderWidth: 1,
                    borderRadius: 4,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                onClick: (evt, elements) => {
                    if (elements.length) {
                        const idx = elements[0].index;
                        const port = heatmap[idx].port;
                        filterByPort(networkPortFilter === port ? null : port);
                    }
                },
                plugins: {
                    ...CHART_DEFAULTS.plugins,
                    legend: { display: false },
                    tooltip: {
                        ...CHART_DEFAULTS.plugins.tooltip,
                        callbacks: {
                            title: (items) => {
                                const port = heatmap[items[0].dataIndex].port;
                                return `:${port} — ${portInfo(port).name}`;
                            },
                            label: (item) => {
                                const port = heatmap[item.dataIndex].port;
                                const info = portInfo(port);
                                return [`${item.raw} assets`, info.desc ? `  ${info.desc}` : ''].filter(Boolean);
                            },
                        },
                    },
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#93A69E', font: { family: 'IBM Plex Mono', size: 10 } } },
                    y: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', precision: 0 } },
                },
            },
        });
    }
}

window.filterByPort = function(port) {
    console.log('[filterByPort] called with port:', port, typeof port);
    networkPortFilter = port;
    const container = document.getElementById('network-content');
    if (!container) return;
    renderPortsTab(container).catch(e => {
        console.error('[filterByPort] render error:', e);
        container.innerHTML = renderErrorState(e.message);
    });
};

// ---------------------------------------------------------------------------
// Asset Detail Slide Panel (used by network & other tables)
// ---------------------------------------------------------------------------
window.openAssetPanel = async function(fqdn) {
    closeAssetPanel();

    // Backdrop
    const backdrop = document.createElement('div');
    backdrop.id = 'asset-panel-backdrop';
    backdrop.className = 'asset-panel-backdrop';
    backdrop.onclick = closeAssetPanel;
    document.body.appendChild(backdrop);

    // Panel shell
    const panel = document.createElement('div');
    panel.id = 'asset-panel';
    panel.className = 'asset-panel';
    panel.innerHTML = `
        <div class="asset-panel-header">
            <div>
                <div class="text-xs text-slate-500 mb-0.5">Asset Details</div>
                <div class="font-mono text-sm font-semibold text-white truncate max-w-[280px]">${esc(fqdn)}</div>
            </div>
            <div class="flex items-center gap-2">
                <button onclick="navigateTo('detail', {id: '${esc(fqdn)}'}); closeAssetPanel();"
                        class="btn-secondary text-xs py-1 px-2">
                    Full page ${ICONS.externalLink}
                </button>
                <button onclick="closeAssetPanel()" class="asset-panel-close">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="w-4 h-4"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
        </div>
        <div class="asset-panel-body" id="asset-panel-body">
            <div class="flex items-center justify-center py-16">
                <div class="flex flex-col items-center gap-3">
                    <div class="w-6 h-6 border-2 border-accent/30 border-t-accent rounded-full animate-spin"></div>
                    <span class="text-xs text-slate-500">Loading...</span>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(panel);

    // Animate in
    requestAnimationFrame(() => panel.classList.add('asset-panel-open'));

    // Fetch asset data
    try {
        const asset = await api(`/assets/${encodeURIComponent(fqdn)}`);
        const body = document.getElementById('asset-panel-body');
        if (body) body.innerHTML = renderAssetPanelContent(asset);
    } catch (e) {
        const body = document.getElementById('asset-panel-body');
        if (body) body.innerHTML = renderErrorState(e.message);
    }
};

window.closeAssetPanel = function() {
    const panel = document.getElementById('asset-panel');
    const backdrop = document.getElementById('asset-panel-backdrop');
    if (panel) {
        panel.classList.remove('asset-panel-open');
        setTimeout(() => panel.remove(), 300);
    }
    if (backdrop) backdrop.remove();
};

// Close panel on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAssetPanel();
});

function renderAssetPanelContent(asset) {
    const dns = asset.dns || {};
    const net = asset.network || {};
    const asn = net.asn || {};
    const web = asset.web || [];
    const tls = asset.tls || [];
    const services = asset.services || [];
    const findings = asset.findings || [];
    const cmdb = asset.cmdb || {};
    const ports = net.open_ports || [];

    // Group findings by severity
    const sevCounts = {};
    findings.forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });

    return `
        <!-- Identity -->
        <div class="mb-4">
            <div class="flex flex-wrap items-center gap-2 mb-2">
                ${(asset.tags || []).map(t => `<span class="badge badge-info">${esc(t)}</span>`).join('')}
                ${cmdb.gap_type ? gapBadge(cmdb.gap_type) : cmdb.in_cmdb ? '<span class="badge badge-low">In CMDB</span>' : ''}
            </div>
            <div class="text-xs text-slate-500">
                Sources: ${(asset.source || []).join(', ')} · Scan: ${esc(asset.scan_id)}
            </div>
        </div>

        <!-- Summary grid -->
        <div class="grid grid-cols-2 gap-2 mb-4">
            <div class="bg-[#0B100E] rounded-lg p-3 border border-surface-border">
                <div class="text-[10px] text-slate-500 uppercase tracking-wider mb-1">IP Addresses</div>
                <div class="font-mono text-xs text-white">${(dns.a || []).join(', ') || '—'}</div>
                ${dns.cname_chain && dns.cname_chain.length ? `
                    <div class="text-[10px] text-slate-500 mt-1">CNAME: ${dns.cname_chain.slice(0,2).join(' → ')}</div>
                ` : ''}
            </div>
            <div class="bg-[#0B100E] rounded-lg p-3 border border-surface-border">
                <div class="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Network</div>
                <div class="text-xs text-white">${esc(net.cdn || 'Direct')}</div>
                <div class="text-[10px] text-slate-500 mt-0.5">${esc(asn.org || '—')}</div>
                ${net.waf ? `<div class="text-[10px] text-slate-500 mt-0.5">WAF: <span class="text-accent">${esc(net.waf.provider)}</span></div>` : ''}
            </div>
        </div>

        <!-- Open Ports -->
        ${ports.length ? `
            <div class="mb-4">
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Open Ports (${ports.length})</div>
                <div class="flex flex-wrap gap-1.5">
                    ${ports.map(p => {
                        const info = portInfo(p.port);
                        const cat = portCategoryStyle(info.category);
                        return `
                            <div class="flex items-center gap-1.5 px-2 py-1 rounded-md text-xs"
                                 style="background:${cat.bg}; border:1px solid ${cat.border}40; color:${cat.text}">
                                <span class="font-mono font-bold">:${p.port}</span>
                                <span style="opacity:0.7">${esc(info.name)}</span>
                                ${info.risk === 'critical' || info.risk === 'high' ? `<span class="badge ${PORT_RISK_BADGE[info.risk]}" style="font-size:9px;padding:1px 4px">${info.risk}</span>` : ''}
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        ` : ''}

        <!-- Findings summary -->
        ${findings.length ? `
            <div class="mb-4">
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Findings (${findings.length})</div>
                <div class="flex flex-wrap gap-1.5 mb-2">
                    ${Object.entries(sevCounts).sort(([a],[b]) => SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b)).map(([sev, cnt]) =>
                        `<span class="badge badge-${sev}">${cnt} ${sev}</span>`
                    ).join('')}
                </div>
                <div class="space-y-1 max-h-40 overflow-y-auto">
                    ${findings.slice(0, 8).map(f => `
                        <div class="flex items-center gap-2 text-xs py-1 border-b border-surface-border/50">
                            ${severityBadge(f.severity)}
                            <span class="text-slate-300 flex-1 truncate">${esc(f.name || f.template_id)}</span>
                        </div>
                    `).join('')}
                    ${findings.length > 8 ? `<div class="text-xs text-slate-500 pt-1">+${findings.length - 8} more</div>` : ''}
                </div>
            </div>
        ` : ''}

        <!-- Web services -->
        ${web.length ? `
            <div class="mb-4">
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Web Services (${web.length})</div>
                <div class="space-y-2">
                    ${web.slice(0, 3).map(w => `
                        <div class="bg-[#0B100E] rounded-lg p-3 border border-surface-border">
                            <div class="flex items-center gap-2 mb-1">
                                <a href="${esc(w.url)}" target="_blank" rel="noopener noreferrer"
                                   onclick="event.stopPropagation()"
                                   class="font-mono text-xs text-accent hover:text-accent-light truncate max-w-[220px]">${esc(w.url)}</a>
                                <span class="badge ${(w.status_code >= 200 && w.status_code < 400) ? 'badge-low' : 'badge-high'}">${w.status_code}</span>
                            </div>
                            ${w.title ? `<div class="text-xs text-slate-400 truncate">${esc(w.title)}</div>` : ''}
                            ${w.tech && w.tech.length ? `
                                <div class="text-[10px] text-slate-500 mt-1">${w.tech.slice(0,5).map(t => esc(t.name || t)).join(', ')}</div>
                            ` : ''}
                        </div>
                    `).join('')}
                    ${web.length > 3 ? `<div class="text-xs text-slate-500">+${web.length-3} more services</div>` : ''}
                </div>
            </div>
        ` : ''}

        <!-- TLS issues -->
        ${tls.length ? `
            <div class="mb-2">
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">TLS Certificates (${tls.length})</div>
                ${tls.slice(0, 2).map(t => {
                    const issues = [t.expired && 'Expired', t.self_signed && 'Self-Signed', t.mismatched && 'Mismatched', t.revoked && 'Revoked'].filter(Boolean);
                    return `
                        <div class="flex items-center justify-between text-xs py-1.5 border-b border-surface-border/50">
                            <span class="text-slate-400 font-mono">:${t.port}</span>
                            <span class="text-slate-300 truncate max-w-[160px] mx-2">${esc(t.subject || t.issuer || '—')}</span>
                            <span class="${(t.days_to_expiry != null && t.days_to_expiry < 0) ? 'text-red-400' : t.days_to_expiry < 30 ? 'text-yellow-400' : 'text-green-400'}">
                                ${t.days_to_expiry != null ? t.days_to_expiry + 'd' : '—'}
                            </span>
                            ${issues.length ? `<span class="badge badge-high ml-1">${issues[0]}</span>` : ''}
                        </div>
                    `;
                }).join('')}
            </div>
        ` : ''}

        <!-- Service Fingerprints -->
        ${services.length ? `
            <div class="mb-2">
                <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Service Fingerprints (${services.length})</div>
                <div class="space-y-2">
                    ${services.slice(0, 6).map(s => {
                        const fp = s.fingerprint || {};
                        return `
                            <div class="bg-[#0B100E] rounded-lg p-3 border border-surface-border">
                                <div class="flex items-center gap-2 mb-1">
                                    <span class="badge badge-info text-[10px]">${esc(s.service || 'unknown')}</span>
                                    <span class="font-mono text-[11px] text-slate-500">:${s.port}</span>
                                    ${fp.certainty != null ? `
                                        <span class="ml-auto text-[10px] ${confidenceClass(fp.certainty)}">${Math.round(fp.certainty * 100)}%</span>
                                    ` : ''}
                                </div>
                                ${fp.product ? `
                                    <div class="text-xs text-slate-300 truncate">
                                        ${esc(fp.vendor ? fp.vendor + ' ' + fp.product : fp.product)}
                                        ${fp.version ? `<span class="text-slate-500 font-mono ml-1">${esc(fp.version)}</span>` : ''}
                                    </div>
                                ` : ''}
                                ${s.banner && !fp.product ? `
                                    <div class="font-mono text-[10px] text-slate-500 truncate mt-0.5">${esc(s.banner)}</div>
                                ` : ''}
                            </div>
                        `;
                    }).join('')}
                    ${services.length > 6 ? `<div class="text-xs text-slate-500">+${services.length - 6} more</div>` : ''}
                </div>
            </div>
        ` : ''}
    `;
}

async function renderTechTab(el) {
    const data = await api('/network/tech');
    const summary = data.summary || [];
    const details = data.details || [];

    el.innerHTML = `
        <div class="card p-5 mb-4">
            <h3 class="text-sm font-semibold text-slate-300 mb-4">Technology Distribution</h3>
            <div class="chart-container" style="height: 360px;">
                <canvas id="chart-tech-dist"></canvas>
            </div>
        </div>
        <div class="card overflow-hidden">
            <div class="overflow-x-auto" style="max-height: 400px; overflow-y: auto;">
                <table class="data-table">
                    <thead><tr><th>Technology</th><th>Version</th><th>Count</th><th>Share</th></tr></thead>
                    <tbody>
                        ${details.map(d => {
                            const total = summary.reduce((a, s) => a + s.count, 0) || 1;
                            const pct = (d.count / total * 100).toFixed(1);
                            return `
                                <tr>
                                    <td class="font-medium">${esc(d.name)}</td>
                                    <td class="font-mono text-xs text-slate-400">${esc(d.version || '-')}</td>
                                    <td>${fmt(d.count)}</td>
                                    <td>
                                        <div class="flex items-center gap-2">
                                            <div class="flex-1 h-1.5 bg-surface-border rounded-full overflow-hidden max-w-[100px]">
                                                <div class="h-full bg-accent rounded-full" style="width: ${pct}%"></div>
                                            </div>
                                            <span class="text-xs text-slate-500">${pct}%</span>
                                        </div>
                                    </td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    if (summary.length) {
        const top20 = summary.slice(0, 20);
        createChart('chart-tech-dist', {
            type: 'bar',
            data: {
                labels: top20.map(t => t.name),
                datasets: [{
                    data: top20.map(t => t.count),
                    backgroundColor: 'rgba(47, 217, 176, 0.6)',
                    borderColor: '#2FD9B0',
                    borderWidth: 1,
                    borderRadius: 4,
                    barThickness: 16,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                indexAxis: 'y',
                plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
                scales: {
                    x: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', precision: 0 } },
                    y: { grid: { display: false }, ticks: { color: '#93A69E', font: { size: 11 } } },
                },
            },
        });
    }
}

async function renderCDNTab(el) {
    const data = await api('/network/cdn');
    const items = Array.isArray(data) ? data : (data.summary || []);
    const wafItems = data.waf || [];

    el.innerHTML = `
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">CDN Provider Distribution</h3>
                <div class="chart-container" style="height: 280px;">
                    <canvas id="chart-cdn-detail"></canvas>
                </div>
            </div>
            <div class="card overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="data-table">
                        <thead><tr><th>CDN Provider</th><th>Assets</th><th>Share</th></tr></thead>
                        <tbody>
                            ${items.map(c => `
                                <tr>
                                    <td class="font-medium">${esc(c.cdn)}</td>
                                    <td>${fmt(c.count)}</td>
                                    <td>
                                        <div class="flex items-center gap-2">
                                            <div class="flex-1 h-1.5 bg-surface-border rounded-full overflow-hidden max-w-[120px]">
                                                <div class="h-full bg-accent rounded-full" style="width: ${c.pct || 0}%"></div>
                                            </div>
                                            <span class="text-xs text-slate-500">${fmtPct(c.pct)}</span>
                                        </div>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        ${wafItems.length ? `
        <div class="card overflow-hidden">
            <div class="px-5 pt-4 pb-2 flex items-baseline justify-between">
                <h3 class="text-sm font-semibold text-slate-300">WAF Providers</h3>
                <span class="text-[10px] text-slate-500 font-mono">cdncheck · waf-detect</span>
            </div>
            <div class="overflow-x-auto">
                <table class="data-table">
                    <thead><tr><th>WAF Provider</th><th>Assets</th><th>Avg confidence</th><th>Fingerprinted</th></tr></thead>
                    <tbody>
                        ${wafItems.map(w => `
                            <tr>
                                <td class="font-medium">${esc(w.waf_provider)}</td>
                                <td>${fmt(w.count)}</td>
                                <td>${fmtPct((w.avg_confidence || 0) * 100)}</td>
                                <td>${fmt(w.fingerprinted)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>` : ''}
    `;

    if (items.length) {
        const palette = ['#2FD9B0', '#3b82f6', '#8b5cf6', '#ec4899', '#f97316', '#10b981', '#eab308', '#6E827A'];
        createChart('chart-cdn-detail', {
            type: 'doughnut',
            data: {
                labels: items.map(c => c.cdn),
                datasets: [{
                    data: items.map(c => c.count),
                    backgroundColor: items.map((_, i) => palette[i % palette.length]),
                    borderWidth: 0,
                    hoverOffset: 8,
                }],
            },
            options: { ...CHART_DEFAULTS, cutout: '55%', plugins: { ...CHART_DEFAULTS.plugins, legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' } } },
        });
    }
}

async function renderASNTab(el) {
    const data = await api('/network/asn');
    const items = Array.isArray(data) ? data : [];
    const maxCount = items.length ? Math.max(...items.map(a => a.count)) : 1;

    el.innerHTML = `
        <div class="card p-5 mb-4">
            <h3 class="text-sm font-semibold text-slate-300 mb-4">Hosting Provider Distribution</h3>
            <div class="chart-container" style="height: ${Math.max(280, items.length * 24)}px;">
                <canvas id="chart-asn-dist"></canvas>
            </div>
        </div>
        <div class="card overflow-hidden">
            <div class="overflow-x-auto">
                <table class="data-table">
                    <thead><tr><th>ASN</th><th>Organization</th><th>Assets</th><th>Share</th></tr></thead>
                    <tbody>
                        ${items.map(a => {
                            const pct = (a.count / maxCount * 100).toFixed(1);
                            return `
                                <tr>
                                    <td class="font-mono text-xs text-slate-400">AS${a.asn_number || '?'}</td>
                                    <td class="font-medium">${esc(a.asn_org || 'Unknown')}</td>
                                    <td>${fmt(a.count)}</td>
                                    <td>
                                        <div class="flex items-center gap-2">
                                            <div class="flex-1 h-1.5 bg-surface-border rounded-full overflow-hidden max-w-[120px]">
                                                <div class="h-full bg-blue-500 rounded-full" style="width: ${pct}%"></div>
                                            </div>
                                            <span class="text-xs text-slate-500">${pct}%</span>
                                        </div>
                                    </td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    if (items.length) {
        createChart('chart-asn-dist', {
            type: 'bar',
            data: {
                labels: items.map(a => (a.asn_org || 'Unknown').substring(0, 30)),
                datasets: [{
                    data: items.map(a => a.count),
                    backgroundColor: 'rgba(59, 130, 246, 0.6)',
                    borderColor: '#3b82f6',
                    borderWidth: 1,
                    borderRadius: 4,
                    barThickness: 16,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                indexAxis: 'y',
                plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
                scales: {
                    x: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', precision: 0 } },
                    y: { grid: { display: false }, ticks: { color: '#93A69E', font: { size: 10 } } },
                },
            },
        });
    }
}

window.switchNetworkTab = function(tab) {
    if (tab !== 'ports') {
        networkPortFilter = null;
        _portsData = null;
        _portDetailCache = {};
    }
    networkTab = tab;
    document.querySelectorAll('.tab-btn').forEach(b => {
        b.classList.toggle('active', b.textContent.trim().toLowerCase().startsWith(tab));
    });
    renderNetworkTab();
};

// ---------------------------------------------------------------------------
// Page: Takeover Verifications
// ---------------------------------------------------------------------------
let takeoverFilter = '';

async function pageTakeovers(el) {
    const data = await api('/takeovers', { status: takeoverFilter });
    const items = data.items || [];
    const summary = data.summary || [];
    const verifiedAt = data.verified_at;

    const counts = { confirmed: 0, likely_fp: 0, unverified: 0 };
    summary.forEach(r => { counts[r.status] = (counts[r.status] || 0) + r.count; });
    const highConf = summary.filter(r => r.status === 'confirmed' && r.confidence === 'high').reduce((a, r) => a + r.count, 0);

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Subdomain Takeover Verification</h1>
                <p class="text-sm text-slate-500 mt-1">
                    Live-verified DNS + HTTP fingerprint results
                    ${verifiedAt ? `&middot; Last run: ${fmtDate(verifiedAt)}` : '&middot; <span class="text-yellow-500">Not yet verified — run <code class="font-mono">./run.sh --stage verify</code></span>'}
                </p>
            </div>
            <div class="text-xs text-slate-500 font-mono bg-surface-light px-3 py-2 rounded-lg border border-surface-border">
                ./run.sh --stage verify
            </div>
        </div>

        ${!items.length && !verifiedAt ? `
            <div class="card p-10 text-center">
                <div class="text-5xl mb-4">🔗</div>
                <p class="text-slate-300 font-medium mb-2">No verification data yet</p>
                <p class="text-sm text-slate-500 mb-4">Run the verify stage to perform live DNS + HTTP fingerprint checks on takeover candidates.</p>
                <code class="text-xs font-mono bg-[#0B100E] px-4 py-2 rounded border border-surface-border text-accent">./run.sh --stage verify</code>
            </div>
        ` : `

        <!-- KPI Cards -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="card kpi-card p-4" data-color="red">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Confirmed</div>
                <div class="text-2xl font-bold text-red-400" data-counter="${counts.confirmed}">0</div>
                <div class="text-xs text-slate-500">${highConf} high confidence</div>
            </div>
            <div class="card kpi-card p-4" data-color="yellow">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Unverified</div>
                <div class="text-2xl font-bold text-yellow-400" data-counter="${counts.unverified}">0</div>
                <div class="text-xs text-slate-500">Could not reach host</div>
            </div>
            <div class="card kpi-card p-4" data-color="green">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Likely False Positive</div>
                <div class="text-2xl font-bold text-green-400" data-counter="${counts.likely_fp}">0</div>
                <div class="text-xs text-slate-500">No fingerprint match</div>
            </div>
            <div class="card kpi-card p-4" data-color="cyan">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Total Checked</div>
                <div class="text-2xl font-bold text-white" data-counter="${items.length || (counts.confirmed + counts.likely_fp + counts.unverified)}">0</div>
                <div class="text-xs text-slate-500">Candidates processed</div>
            </div>
        </div>

        <!-- Chart + Legend -->
        ${counts.confirmed || counts.likely_fp || counts.unverified ? `
        <div class="card p-5 mb-4">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 items-center">
                <div>
                    <h3 class="text-sm font-semibold text-slate-300 mb-4">Verification Status Breakdown</h3>
                    <div class="chart-container" style="height: 200px;">
                        <canvas id="chart-takeover-status"></canvas>
                    </div>
                </div>
                <div class="space-y-3 text-sm">
                    <div class="flex items-start gap-3">
                        <span class="mt-0.5 w-2.5 h-2.5 rounded-full bg-red-500 shrink-0"></span>
                        <div><span class="text-white font-medium">Confirmed</span> — CNAME target is NXDOMAIN and/or HTTP fingerprint matched an unclaimed-resource page.</div>
                    </div>
                    <div class="flex items-start gap-3">
                        <span class="mt-0.5 w-2.5 h-2.5 rounded-full bg-yellow-400 shrink-0"></span>
                        <div><span class="text-white font-medium">Unverified</span> — Host could not be reached (connection timeout or DNS failure). Re-check manually.</div>
                    </div>
                    <div class="flex items-start gap-3">
                        <span class="mt-0.5 w-2.5 h-2.5 rounded-full bg-green-500 shrink-0"></span>
                        <div><span class="text-white font-medium">Likely FP</span> — No CNAME found, active CDN/provider serving real content, or fingerprint did not match.</div>
                    </div>
                </div>
            </div>
        </div>
        ` : ''}

        <!-- Filter Tabs -->
        <div class="tab-bar">
            <button class="tab-btn ${!takeoverFilter ? 'active' : ''}" onclick="filterTakeovers('')">
                All (${counts.confirmed + counts.likely_fp + counts.unverified})
            </button>
            <button class="tab-btn ${takeoverFilter === 'confirmed' ? 'active' : ''}" onclick="filterTakeovers('confirmed')">
                Confirmed (${counts.confirmed})
            </button>
            <button class="tab-btn ${takeoverFilter === 'unverified' ? 'active' : ''}" onclick="filterTakeovers('unverified')">
                Unverified (${counts.unverified})
            </button>
            <button class="tab-btn ${takeoverFilter === 'likely_fp' ? 'active' : ''}" onclick="filterTakeovers('likely_fp')">
                Likely FP (${counts.likely_fp})
            </button>
        </div>

        <!-- Table -->
        <div class="card overflow-hidden">
            <div class="overflow-x-auto" style="max-height: 620px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Confidence</th>
                            <th>FQDN</th>
                            <th>Service</th>
                            <th>Live CNAME Chain</th>
                            <th>HTTP</th>
                            <th>Fingerprint</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${items.length ? items.map(r => `
                            <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(r.fqdn)}'})">
                                <td>${takeoverStatusBadge(r.status)}</td>
                                <td>${takeoverConfBadge(r.confidence)}</td>
                                <td class="font-mono text-xs text-accent">${esc(r.fqdn)}</td>
                                <td class="text-xs text-slate-400">${esc(r.service || '-')}</td>
                                <td class="font-mono text-xs text-slate-400 max-w-[200px] truncate">${(r.live_cname_chain || []).join(' → ') || '<span class="text-slate-600">none</span>'}</td>
                                <td class="font-mono text-xs ${r.http_status_code === -1 ? 'text-slate-600' : r.http_status_code >= 400 ? 'text-orange-400' : 'text-slate-300'}">${r.http_status_code === -1 ? 'N/A' : r.http_status_code}</td>
                                <td>${r.http_fingerprint_matched ? `<span class="text-red-400 text-xs font-medium">✓ ${esc(r.http_matched_snippet)}</span>` : '<span class="text-slate-600 text-xs">—</span>'}</td>
                                <td class="text-xs text-slate-500 max-w-[280px]">${(r.evidence || []).slice(0, 2).map(e => esc(e)).join('<br>')}</td>
                            </tr>
                        `).join('') : `<tr><td colspan="8">${renderEmptyState('No results', 'Try a different filter')}</td></tr>`}
                    </tbody>
                </table>
            </div>
        </div>
        `}
    `;

    requestAnimationFrame(() => {
        document.querySelectorAll('[data-counter]').forEach(el => {
            const val = parseFloat(el.getAttribute('data-counter'));
            if (!isNaN(val)) animateCounter(el, val);
        });
    });

    if (counts.confirmed || counts.likely_fp || counts.unverified) {
        createChart('chart-takeover-status', {
            type: 'doughnut',
            data: {
                labels: ['Confirmed', 'Unverified', 'Likely FP'],
                datasets: [{
                    data: [counts.confirmed, counts.unverified, counts.likely_fp],
                    backgroundColor: ['#ef4444', '#eab308', '#10b981'],
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                cutout: '65%',
                plugins: {
                    ...CHART_DEFAULTS.plugins,
                    legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
                },
            },
        });
    }
}

function takeoverStatusBadge(status) {
    const map = {
        confirmed:  'badge-critical',
        unverified: 'badge-medium',
        likely_fp:  'badge-info',
    };
    const labels = { confirmed: 'CONFIRMED', unverified: 'UNVERIFIED', likely_fp: 'LIKELY FP' };
    return `<span class="badge ${map[status] || 'badge-info'}">${labels[status] || esc(status)}</span>`;
}

function takeoverConfBadge(conf) {
    const map = { high: 'text-red-400', medium: 'text-yellow-400', low: 'text-slate-500' };
    return `<span class="text-xs font-semibold ${map[conf] || 'text-slate-500'}">${esc(conf || '-')}</span>`;
}

window.filterTakeovers = function(status) {
    takeoverFilter = status;
    const el = document.getElementById('page-content');
    if (el) pageTakeovers(el);
};

// ---------------------------------------------------------------------------
// Page: Services / Fingerprints
// ---------------------------------------------------------------------------
let serviceState = { service: '', search: '', limit: 500 };

async function pageServices(el) {
    const [data, inv] = await Promise.all([
        api('/services', serviceState),
        api('/services/inventory'),
    ]);
    const items = data.items || [];
    const summary = data.summary || [];
    const inventory = inv.items || [];

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Service Fingerprints</h1>
                <p class="text-sm text-slate-500 mt-1">${fmt(items.length)} services fingerprinted</p>
            </div>
        </div>

        <!-- Service type filter pills -->
        <div class="flex flex-wrap gap-2 mb-4">
            <button onclick="filterServices('service', '')"
                    class="card px-3 py-1.5 text-xs font-medium transition-all ${!serviceState.service ? 'ring-1 ring-accent text-accent' : 'card-interactive text-slate-400'}">
                All
            </button>
            ${summary.map(s => `
                <button onclick="filterServices('service', '${esc(s.service || '')}')"
                        class="card px-3 py-1.5 text-xs font-medium transition-all ${s.service === serviceState.service ? 'ring-1 ring-accent text-accent' : 'card-interactive text-slate-400'}">
                    ${esc(s.service || 'unknown')}
                    <span class="text-slate-500 ml-1">${fmt(s.count)}</span>
                </button>
            `).join('')}
        </div>

        <!-- Search -->
        <div class="flex flex-wrap items-center gap-3 mb-4">
            <div class="relative flex-1 min-w-[240px] max-w-md">
                <div class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">${ICONS.search}</div>
                <input type="text" id="service-search" class="search-input"
                       placeholder="Search FQDN, product, vendor…"
                       value="${esc(serviceState.search)}">
            </div>
        </div>

        <!-- Services table -->
        ${items.length ? `
            <div class="card overflow-hidden mb-6">
                <div class="overflow-x-auto" style="max-height: 520px; overflow-y: auto;">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>FQDN</th>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Product</th>
                                <th>Version</th>
                                <th>CPE</th>
                                <th>OS</th>
                                <th>Confidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${items.map(s => {
                                const os = [s.fp_os_vendor, s.fp_os_product, s.fp_os_version].filter(Boolean).join(' ');
                                const cpe = s.fp_cpe23 || '';
                                return `
                                    <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(s.fqdn)}'})">
                                        <td class="font-mono text-xs text-accent">${esc(s.fqdn)}</td>
                                        <td class="font-mono text-xs">${s.port}${s.protocol ? `<span class="text-slate-500">/${s.protocol}</span>` : ''}</td>
                                        <td>${esc(s.service || '-')}</td>
                                        <td>${esc(s.fp_product || '-')}</td>
                                        <td class="font-mono text-xs text-slate-400">${esc(s.fp_version || '-')}</td>
                                        <td class="font-mono text-xs text-slate-500" title="${esc(cpe)}">${cpe ? cpe.substring(0, 32) + (cpe.length > 32 ? '…' : '') : '-'}</td>
                                        <td class="text-xs text-slate-400">${esc(os || '-')}</td>
                                        <td><span class="${confidenceClass(s.fp_certainty)}">${s.fp_certainty != null ? Math.round(s.fp_certainty * 100) + '%' : '-'}</span></td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : renderEmptyState('No service fingerprints', 'Run a scan with Nerva to populate service data')}

        <!-- Software inventory -->
        ${inventory.length ? `
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Software Inventory</h3>
                <div class="overflow-x-auto">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Product</th>
                                <th>Vendor</th>
                                <th>Version</th>
                                <th>CPE</th>
                                <th>Hosts</th>
                                <th>Avg Confidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${inventory.map(i => {
                                const cpe = i.cpe23 || '';
                                return `
                                    <tr>
                                        <td class="font-medium">${esc(i.product)}</td>
                                        <td class="text-slate-400">${esc(i.vendor || '-')}</td>
                                        <td class="font-mono text-xs text-slate-400">${esc(i.version || '-')}</td>
                                        <td class="font-mono text-xs text-slate-500" title="${esc(cpe)}">${cpe ? cpe.substring(0, 38) + (cpe.length > 38 ? '…' : '') : '-'}</td>
                                        <td><span class="font-bold text-white">${fmt(i.host_count)}</span></td>
                                        <td><span class="${confidenceClass(i.avg_certainty)}">${i.avg_certainty != null ? Math.round(i.avg_certainty * 100) + '%' : '-'}</span></td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : ''}
    `;

    const searchEl = document.getElementById('service-search');
    if (searchEl) {
        searchEl.addEventListener('input', debounce(e => {
            serviceState.search = e.target.value;
            renderCurrentPage();
        }, 300));
    }
}

function filterServices(key, val) {
    serviceState[key] = val;
    renderCurrentPage();
}

// ---------------------------------------------------------------------------
// Page: New Scan
// ---------------------------------------------------------------------------
let _scanPollTimer = null;
let _logPollTimer = null;

async function pageScans(el) {
    const [scansData, activeData] = await Promise.all([
        api('/scans'),
        api('/scans/active'),
    ]);
    const archives = scansData.archives || [];
    const active = activeData.status === 'running' ? activeData : (scansData.active || null);
    const lastCompleted = _read_scan_state_from(activeData);

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Scan Management</h1>
                <p class="text-sm text-slate-500 mt-1">Launch on-demand scans and browse scan history</p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-5 gap-6">
            <!-- Left: Scan Form -->
            <div class="lg:col-span-2 space-y-4">
                <!-- Active Scan Status -->
                ${active ? _renderActiveScan(active) : lastCompleted && lastCompleted.status !== 'idle' ? _renderLastScanResult(lastCompleted) : ''}

                <!-- New Scan Form -->
                <div class="card p-5">
                    <div class="flex items-center justify-between mb-4 gap-2">
                        <h3 class="text-sm font-semibold text-slate-300">New Scan</h3>
                        <div class="flex items-center gap-2 min-w-0">
                            <span id="scan-targets-file" class="scan-file-chip hidden"></span>
                            <span id="subdomain-count" class="subdomain-counter">0 targets</span>
                        </div>
                    </div>
                    <textarea
                        id="scan-subdomains"
                        class="scan-textarea mb-3"
                        rows="12"
                        placeholder="Enter targets one per line, or drop a targets.txt / .csv here&#10;&#10;example.com&#10;app.example.com&#10;https://api.example.com/login&#10;203.0.113.0/28&#10;&#10;# starts a comment"
                        ${active ? 'disabled' : ''}
                    ></textarea>
                    <input id="scan-root-domains" type="text"
                           placeholder="Root domains for subfinder + CT enrichment — optional, comma-separated (e.g. example.com)"
                           class="w-full text-xs bg-[#0B100E] border border-slate-700 rounded px-2 py-1.5 mb-3 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-accent"
                           ${active ? 'disabled' : ''} />
                    <div class="scan-cmdb-row mb-3">
                        <div class="flex items-center justify-between gap-2">
                            <div class="min-w-0">
                                <div class="text-xs text-slate-400">CMDB export <span class="text-slate-600">— optional CSV</span></div>
                                <div id="scan-cmdb-status" class="text-[11px] text-slate-600 truncate">Not attached — falls back to data/input/cmdb_export.csv</div>
                            </div>
                            <div class="flex items-center gap-1.5 shrink-0">
                                <input id="scan-cmdb-file" type="file" accept=".csv,text/csv" class="hidden" onchange="attachCmdbFile(this)" />
                                <button onclick="document.getElementById('scan-cmdb-file').click()" class="btn-secondary text-xs py-1 px-2" ${active ? 'disabled' : ''}>
                                    ${ICONS.upload}<span>Choose CSV</span>
                                </button>
                                <button id="scan-cmdb-clear" onclick="clearCmdbFile()" class="btn-secondary text-xs py-1 px-2 hidden" ${active ? 'disabled' : ''}>Clear</button>
                            </div>
                        </div>
                        <p class="text-[10px] text-slate-600 mt-1">Used for CMDB matching, CMDB Livecheck and CMDB-only Tenable scope. Needs an <span class="font-mono">fqdn</span>, <span class="font-mono">hostname</span> or <span class="font-mono">name</span> column.</p>
                        <p id="scan-cmdb-warn" class="text-[11px] text-yellow-400/80 mt-1 hidden">CMDB Livecheck validates CMDB records — attach an export unless data/input/cmdb_export.csv is in place.</p>
                    </div>
                    <div class="flex items-center gap-3 mb-3">
                        <span class="text-xs text-slate-400 whitespace-nowrap">Mode:</span>
                        <label class="flex items-center gap-1.5 cursor-pointer">
                            <input type="radio" name="scan-mode" value="recon" onchange="_updateCmdbHint()" checked
                                   class="accent-[#5FE8C6]" ${active ? 'disabled' : ''}>
                            <span class="text-xs text-slate-300">Recon</span>
                        </label>
                        <label class="flex items-center gap-1.5 cursor-pointer">
                            <input type="radio" name="scan-mode" value="bounty" onchange="_updateCmdbHint()"
                                   class="accent-[#5FE8C6]" ${active ? 'disabled' : ''}>
                            <span class="text-xs text-slate-300">Bug Bounty Prepare</span>
                        </label>
                        <label class="flex items-center gap-1.5 cursor-pointer">
                            <input type="radio" name="scan-mode" value="livecheck" onchange="_updateCmdbHint()"
                                   class="accent-[#5FE8C6]" ${active ? 'disabled' : ''}>
                            <span class="text-xs text-slate-300">CMDB Livecheck</span>
                        </label>
                    </div>
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-2">
                            <input id="scan-targets-input" type="file" accept=".txt,.csv,.lst,.list,text/plain,text/csv" class="hidden" onchange="uploadTargetsFile(this.files[0]); this.value = ''" />
                            <button onclick="document.getElementById('scan-targets-input').click()" class="btn-secondary" ${active ? 'disabled' : ''}>
                                ${ICONS.upload} Upload targets
                            </button>
                        </div>
                        <button id="btn-start-scan" onclick="startScan()" class="btn-primary" ${active ? 'disabled' : ''}>
                            ${ICONS.play}
                            ${active ? 'Scan Running...' : 'Start Scan'}
                        </button>
                    </div>
                </div>

                <!-- Pipeline Configuration -->
                <div class="card p-4">
                    <div class="flex items-center justify-between mb-3">
                        <h4 class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Pipeline Stages</h4>
                        <label class="flex items-center gap-2 cursor-pointer select-none">
                            <span class="text-[11px] text-slate-500">Full Pipeline</span>
                            <input type="checkbox" id="scan-full-pipeline" checked
                                   onchange="toggleFullPipeline(this)"
                                   class="w-3.5 h-3.5 rounded accent-[#5FE8C6]"
                                   ${active ? 'disabled' : ''}>
                        </label>
                    </div>
                    <div id="stage-checkboxes" class="space-y-1 text-xs" style="display:none">
                        ${PIPELINE_STAGES.map(s => `
                            <label class="flex items-center gap-2.5 cursor-pointer py-1 px-1 rounded hover:bg-white/[0.03] transition-colors select-none ${s.required ? 'opacity-60' : ''}">
                                <input type="checkbox" class="stage-checkbox w-3.5 h-3.5 rounded accent-[#5FE8C6]"
                                       value="${s.id}" checked
                                       ${s.required || active ? 'disabled' : ''}>
                                <span class="text-slate-300 flex-1">${s.name}</span>
                                <span class="text-slate-600 font-mono text-[10px]">${s.tool}</span>
                            </label>
                        `).join('')}
                        <p class="text-[10px] text-slate-600 pt-1">Normalize & Load are always included.</p>
                    </div>
                </div>

                <!-- Import Scan -->
                <div class="card p-4">
                    <h4 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                        ${ICONS.upload} Import Scan
                    </h4>
                    <p class="text-xs text-slate-500 mb-3">Load an archived <code class="text-slate-300">.duckdb</code> or <code class="text-slate-300">.parquet</code> file into the scan history.</p>
                    <div class="space-y-2">
                        <input id="import-scan-id" type="text" placeholder="Scan ID (YYYYMMDD_HHMMSS) — optional"
                               class="w-full text-xs bg-[#0B100E] border border-slate-700 rounded px-2 py-1.5 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-accent" />
                        <input id="import-notes" type="text" placeholder="Notes — optional"
                               class="w-full text-xs bg-[#0B100E] border border-slate-700 rounded px-2 py-1.5 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-accent" />
                        <label class="block">
                            <input id="import-file" type="file" accept=".duckdb,.parquet" class="hidden" onchange="importScan()" />
                            <span onclick="document.getElementById('import-file').click()"
                                  class="btn-secondary text-xs py-1.5 px-3 w-full text-center cursor-pointer flex items-center justify-center gap-1.5">
                                ${ICONS.upload} Choose File &amp; Import
                            </span>
                        </label>
                        <div id="import-status" class="text-xs text-slate-500 hidden"></div>
                    </div>
                </div>
            </div>

            <!-- Right: Scan History -->
            <div class="lg:col-span-3">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold text-slate-300 flex items-center gap-2">
                        ${ICONS.archive} Scan Archive
                        <span class="text-xs font-normal text-slate-500">(${archives.length} scan${archives.length !== 1 ? 's' : ''})</span>
                    </h3>
                </div>

                ${archives.length ? `
                    <div class="space-y-3">
                        ${archives.map((a, i) => _renderArchiveCard(a, i === 0)).join('')}
                    </div>
                ` : `
                    <div class="card p-10 text-center">
                        <div class="text-slate-600 mb-3">${ICONS.archive}</div>
                        <p class="text-slate-400 font-medium">No archived scans yet</p>
                        <p class="text-sm text-slate-600 mt-1">Scans are automatically archived when a new scan runs</p>
                    </div>
                `}
            </div>
        </div>
    `;

    // Target counter + drag-and-drop upload
    const textarea = document.getElementById('scan-subdomains');
    const counter = document.getElementById('subdomain-count');
    if (textarea && counter) {
        const updateCount = () => {
            const n = _countTargets(textarea.value);
            counter.textContent = `${fmt(n)} target${n !== 1 ? 's' : ''}`;
            counter.classList.toggle('has-content', n > 0);
        };
        textarea.addEventListener('input', updateCount);
        if (!active) {
            textarea.addEventListener('dragover', e => { e.preventDefault(); textarea.classList.add('scan-dropzone-active'); });
            textarea.addEventListener('dragleave', () => textarea.classList.remove('scan-dropzone-active'));
            textarea.addEventListener('drop', e => {
                e.preventDefault();
                textarea.classList.remove('scan-dropzone-active');
                if (e.dataTransfer.files.length) uploadTargetsFile(e.dataTransfer.files[0]);
            });
        }
    }
    _scanCmdb = null;

    // Poll if scan is running
    if (_scanPollTimer) clearInterval(_scanPollTimer);
    if (_logPollTimer) { clearInterval(_logPollTimer); _logPollTimer = null; }
    if (active) {
        _scanPollTimer = setInterval(async () => {
            try {
                const st = await api('/scans/active');
                if (st.status !== 'running') {
                    clearInterval(_scanPollTimer); _scanPollTimer = null;
                    if (_logPollTimer) { clearInterval(_logPollTimer); _logPollTimer = null; }
                    pageScans(el);
                } else {
                    const stageEl = document.getElementById('scan-current-stage');
                    if (stageEl && st.current_stage) stageEl.textContent = st.current_stage;
                }
            } catch { /* ignore */ }
        }, 5000);
    }
}

function _read_scan_state_from(data) {
    if (!data || data.status === 'idle') return null;
    return data;
}

function _renderActiveScan(active) {
    const stagesLabel = active.stages && active.stages !== 'full'
        ? active.stages.split(',').join(', ')
        : 'Full Pipeline';
    const stageDisplay = active.current_stage || 'Initializing…';
    return `
        <div class="scan-progress">
            <div class="flex items-center gap-3 mb-3">
                <div class="w-6 h-6 border-2 border-accent/30 border-t-accent rounded-full animate-spin"></div>
                <div>
                    <span class="text-sm font-semibold text-white">Scan in Progress</span>
                    <span class="status-badge status-running ml-2">Running</span>
                </div>
            </div>
            <div class="grid grid-cols-2 gap-3 text-xs">
                <div>
                    <span class="text-slate-500">Scan ID:</span>
                    <span class="text-slate-300 font-mono ml-1">${esc(active.scan_id)}</span>
                </div>
                <div>
                    <span class="text-slate-500">Started:</span>
                    <span class="text-slate-300 ml-1">${fmtDate(active.started_at)}</span>
                </div>
                <div>
                    <span class="text-slate-500">Stages:</span>
                    <span class="text-slate-300 ml-1">${esc(stagesLabel)}</span>
                </div>
                <div>
                    <span class="text-slate-500">Mode:</span>
                    <span class="text-slate-300 ml-1">${esc(active.mode || 'recon')}</span>
                </div>
                <div class="col-span-2">
                    <span class="text-slate-500">Current stage:</span>
                    <span id="scan-current-stage" class="text-accent ml-1">${esc(stageDisplay)}</span>
                </div>
            </div>
            <div class="mt-3">
                <button id="debug-log-btn" onclick="toggleDebugLogs()" class="btn-secondary text-xs py-1 px-2">Show logs</button>
                <div id="debug-log-panel" style="display:none" class="mt-2">
                    <pre id="debug-log-content" class="text-xs text-slate-400 font-mono bg-slate-900/60 rounded p-2 max-h-52 overflow-auto whitespace-pre-wrap break-all"></pre>
                </div>
            </div>
            <p class="text-xs text-slate-500 mt-3">Auto-refreshes every 5 seconds.</p>
        </div>
    `;
}

function toggleDebugLogs() {
    const panel = document.getElementById('debug-log-panel');
    const btn = document.getElementById('debug-log-btn');
    if (!panel) return;
    const open = panel.style.display !== 'none';
    if (open) {
        panel.style.display = 'none';
        if (btn) btn.textContent = 'Show logs';
        if (_logPollTimer) { clearInterval(_logPollTimer); _logPollTimer = null; }
    } else {
        panel.style.display = 'block';
        if (btn) btn.textContent = 'Hide logs';
        _fetchDebugLogs();
        _logPollTimer = setInterval(_fetchDebugLogs, 3000);
    }
}

async function _fetchDebugLogs() {
    try {
        const data = await api('/scans/logs?lines=80');
        const el = document.getElementById('debug-log-content');
        if (el && data.lines) {
            el.textContent = data.lines.join('\n');
            el.scrollTop = el.scrollHeight;
        }
    } catch { /* ignore */ }
}

function _renderLastScanResult(scan) {
    const isOk = scan.status === 'completed';
    const icon = isOk ? ICONS.check : ICONS.warning;
    const colorClass = isOk ? 'border-green-500/30 bg-green-500/5' : 'border-red-500/30 bg-red-500/5';
    const statusBadge = isOk
        ? '<span class="status-badge status-completed">Completed</span>'
        : '<span class="status-badge status-failed">Failed</span>';

    return `
        <div class="rounded-xl border ${colorClass} p-4">
            <div class="flex items-center gap-2 mb-2">
                <span class="${isOk ? 'text-green-400' : 'text-red-400'}">${icon}</span>
                <span class="text-sm font-medium text-white">Last Scan</span>
                ${statusBadge}
            </div>
            <div class="text-xs text-slate-400">
                <span class="font-mono">${esc(scan.scan_id)}</span>
                ${scan.finished_at ? ` — finished ${fmtDate(scan.finished_at)}` : ''}
            </div>
            ${scan.error ? `<p class="text-xs text-red-400 mt-2 font-mono">${esc(scan.error.substring(0, 200))}</p>` : ''}
        </div>
    `;
}

function _renderArchiveCard(archive, isLatest) {
    const r = archive.results || {};
    const sevMap = r.findings_by_severity || {};
    const totalFindings = r.total_findings || 0;
    const hasMetrics = r.total_assets > 0;

    const scanDate = archive.archived_at || archive.scan_id;
    let displayDate = archive.scan_id;
    try {
        if (archive.archived_at) displayDate = fmtDate(archive.archived_at);
    } catch { /* keep scan_id */ }

    const sevTotal = Object.values(sevMap).reduce((a, b) => a + b, 0) || 1;
    const sevBarSegments = ['critical', 'high', 'medium', 'low', 'info']
        .filter(s => sevMap[s])
        .map(s => `<div style="width: ${(sevMap[s] / sevTotal) * 100}%; background: ${SEVERITY_COLORS[s]}"></div>`)
        .join('');

    return `
        <div class="archive-card ${isLatest ? 'border-accent/30' : ''}">
            <div class="flex items-start justify-between mb-3">
                <div class="flex items-center gap-3">
                    <div class="timeline-dot ${isLatest ? 'active' : ''}"></div>
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="font-mono text-sm font-medium text-white">${esc(archive.scan_id)}</span>
                            ${isLatest ? '<span class="text-[10px] uppercase tracking-wider text-accent font-semibold">Latest</span>' : ''}
                        </div>
                        <div class="text-xs text-slate-500 flex items-center gap-1 mt-0.5">
                            ${ICONS.clock} ${displayDate}
                            ${archive.input ? ` · ${archive.input.subdomain_count || '?'} subdomains` : ''}
                            ${archive.db_size_bytes ? ` · ${_formatBytes(archive.db_size_bytes)}` : ''}
                        </div>
                    </div>
                </div>
                <div class="flex items-center gap-1">
                    <button onclick="navigateTo('archive', {id: '${esc(archive.scan_id)}'})"
                            class="btn-secondary text-xs py-1 px-2" title="Browse this archive">
                        ${ICONS.eye} View
                    </button>
                    <button onclick="exportScan('${esc(archive.scan_id)}')"
                            class="btn-secondary text-xs py-1 px-2" title="Export as Parquet">
                        ${ICONS.download} Export
                    </button>
                    <button onclick="restoreArchive('${esc(archive.scan_id)}')"
                            class="btn-secondary text-xs py-1 px-2" title="Restore this scan as active">
                        ${ICONS.restore} Restore
                    </button>
                    <button onclick="deleteArchive('${esc(archive.scan_id)}')"
                            class="btn-danger py-1 px-2" title="Delete this archive">
                        ${ICONS.trash}
                    </button>
                </div>
            </div>

            ${hasMetrics ? `
                <div class="grid grid-cols-4 gap-3 mb-3">
                    <div class="bg-[#0B100E] rounded-lg p-2.5 text-center">
                        <div class="text-lg font-bold text-white">${fmt(r.total_assets)}</div>
                        <div class="text-[10px] text-slate-500 uppercase tracking-wider">Assets</div>
                    </div>
                    <div class="bg-[#0B100E] rounded-lg p-2.5 text-center">
                        <div class="text-lg font-bold text-white">${fmt(r.web_assets || 0)}</div>
                        <div class="text-[10px] text-slate-500 uppercase tracking-wider">Web</div>
                    </div>
                    <div class="bg-[#0B100E] rounded-lg p-2.5 text-center">
                        <div class="text-lg font-bold ${totalFindings > 0 ? 'text-orange-400' : 'text-white'}">${fmt(totalFindings)}</div>
                        <div class="text-[10px] text-slate-500 uppercase tracking-wider">Findings</div>
                    </div>
                    <div class="bg-[#0B100E] rounded-lg p-2.5 text-center">
                        <div class="text-lg font-bold ${(r.shadow_it || 0) > 0 ? 'text-red-400' : 'text-white'}">${fmt(r.shadow_it || 0)}</div>
                        <div class="text-[10px] text-slate-500 uppercase tracking-wider">Shadow IT</div>
                    </div>
                </div>

                ${sevBarSegments ? `
                    <div class="mb-2">
                        <div class="flex items-center justify-between mb-1">
                            <span class="text-[10px] text-slate-500 uppercase tracking-wider">Findings by Severity</span>
                            <div class="flex items-center gap-2 text-[10px]">
                                ${Object.entries(sevMap).map(([s, c]) =>
                                    `<span style="color: ${SEVERITY_COLORS[s] || '#6b7280'}">${capitalize(s)}: ${c}</span>`
                                ).join('')}
                            </div>
                        </div>
                        <div class="sev-bar">${sevBarSegments}</div>
                    </div>
                ` : ''}

                <div class="flex items-center gap-4 text-xs text-slate-500">
                    ${r.tls_assets ? `<span>TLS: ${r.tls_assets}</span>` : ''}
                    ${r.in_cmdb != null ? `<span>CMDB: ${r.in_cmdb}/${r.total_assets}</span>` : ''}
                    ${(r.tls_issues || 0) > 0 ? `<span class="text-yellow-500">TLS issues: ${r.tls_issues}</span>` : ''}
                </div>
            ` : `
                <div class="text-xs text-slate-600 italic">No detailed metrics available for this archive</div>
            `}
        </div>
    `;
}

function _formatBytes(bytes) {
    if (!bytes || bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

window.toggleFullPipeline = function(checkbox) {
    const container = document.getElementById('stage-checkboxes');
    if (!container) return;
    container.style.display = checkbox.checked ? 'none' : '';
    if (checkbox.checked) {
        container.querySelectorAll('.stage-checkbox:not(:disabled)').forEach(cb => { cb.checked = true; });
    }
};

function _getSelectedStages() {
    const fp = document.getElementById('scan-full-pipeline');
    if (fp && fp.checked) return '';
    const checked = document.querySelectorAll('.stage-checkbox:checked');
    const ids = Array.from(checked).map(cb => cb.value);
    if (!ids.includes('normalize')) ids.push('normalize');
    if (!ids.includes('load')) ids.push('load');
    return ids.join(',');
}

window.startScan = async function() {
    const textarea = document.getElementById('scan-subdomains');
    const btn = document.getElementById('btn-start-scan');
    if (!textarea || !btn) return;

    const subdomains = textarea.value.trim();
    if (!subdomains) {
        alert('Please enter or upload at least one target');
        return;
    }

    const count = _countTargets(subdomains);
    if (count === 0) {
        alert('No targets found (# starts a comment)');
        return;
    }

    const stages = _getSelectedStages();
    const rootDomainsEl = document.getElementById('scan-root-domains');
    const root_domains = rootDomainsEl ? rootDomainsEl.value.trim() : '';
    const modeEl = document.querySelector('input[name="scan-mode"]:checked');
    const mode = modeEl ? modeEl.value : 'recon';
    const stageInfo = (stages ? `\nStages: ${stages}` : '\nAll pipeline stages will run.')
        + (root_domains ? `\nsubfinder + CT enrichment for: ${root_domains}` : '');
    const modeInfo = mode === 'bounty' ? '\nMode: Bug Bounty Prepare (expanded scanning)'
        : mode === 'livecheck' ? '\nMode: CMDB Livecheck (DNS-only scope validation)' : '';
    const cmdbInfo = _scanCmdb ? `\nCMDB export: ${_scanCmdb.name} (${fmt(_scanCmdb.rows)} rows)` : '';

    if (!confirm(`Start scan with ~${fmt(count)} target${count !== 1 ? 's' : ''}?\n${stageInfo}${modeInfo}${cmdbInfo}\n\nThis will archive the current scan data.`)) {
        return;
    }

    btn.disabled = true;
    btn.innerHTML = `<div class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div> Starting...`;

    try {
        const result = await fetch('/api/scans/new', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subdomains, stages, mode, root_domains, cmdb_csv: _scanCmdb ? _scanCmdb.text : '' }),
        });
        const data = await result.json();

        if (!result.ok) {
            throw new Error(data.detail || 'Failed to start scan');
        }
        if (data.rejected_count) {
            alert(`Scan started with ${fmt(data.subdomain_count)} targets.\n\n`
                + `${fmt(data.rejected_count)} entr${data.rejected_count !== 1 ? 'ies were' : 'y was'} not a hostname, IP or CIDR and ${data.rejected_count !== 1 ? 'were' : 'was'} skipped, e.g.:\n`
                + data.rejected_sample.slice(0, 5).join('\n'));
        }
        _scanCmdb = null;

        const el = document.getElementById('page-content');
        if (el) pageScans(el);
    } catch (e) {
        alert('Error: ' + e.message);
        btn.disabled = false;
        btn.innerHTML = `${ICONS.play} Start Scan`;
    }
};

const SCAN_INPUT_MAX_BYTES = 20 * 1024 * 1024;   // matches _MAX_INPUT_BYTES in app.py
let _scanCmdb = null;   // { name, text, rows } — CMDB export attached to the next scan

// Rough client-side count; the server does the real parsing (URLs → hosts, dedupe)
function _countTargets(text) {
    const seen = new Set();
    text.split('\n').forEach(line => line.split('#')[0].split(/[,;\s]+/).forEach(t => {
        t = t.trim().replace(/^["']|["']$/g, '').toLowerCase();
        if (t) seen.add(t);
    }));
    return seen.size;
}

function _readTextFile(file) {
    return new Promise((resolve, reject) => {
        if (file.size > SCAN_INPUT_MAX_BYTES) {
            reject(new Error(`${file.name} is larger than ${SCAN_INPUT_MAX_BYTES / 1024 / 1024} MB`));
            return;
        }
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result || '').replace(/^﻿/, ''));
        reader.onerror = () => reject(reader.error || new Error('Could not read file'));
        reader.readAsText(file);
    });
}

window.uploadTargetsFile = async function(file) {
    const textarea = document.getElementById('scan-subdomains');
    const chip = document.getElementById('scan-targets-file');
    if (!file || !textarea || textarea.disabled) return;
    try {
        textarea.value = await _readTextFile(file);
    } catch (e) {
        alert('Upload failed: ' + e.message);
        return;
    }
    textarea.dispatchEvent(new Event('input'));
    if (chip) {
        chip.textContent = file.name;
        chip.title = `Loaded from ${file.name} — review or edit below before starting`;
        chip.classList.remove('hidden');
    }
};

window.attachCmdbFile = async function(input) {
    const file = input.files && input.files[0];
    input.value = '';
    if (!file) return;
    let text;
    try {
        text = await _readTextFile(file);
    } catch (e) {
        alert('CMDB upload failed: ' + e.message);
        return;
    }
    const lines = text.split(/\r?\n/).filter(l => l.trim());
    const header = (lines[0] || '').toLowerCase().split(',').map(h => h.trim().replace(/^"|"$/g, ''));
    if (!header.some(h => ['fqdn', 'hostname', 'name'].includes(h))) {
        alert(`${file.name}: no fqdn / hostname / name column in the header row.\n\nFound: ${header.join(', ') || '(empty)'}`);
        return;
    }
    _scanCmdb = { name: file.name, text, rows: Math.max(0, lines.length - 1) };
    _updateCmdbHint();
};

window.clearCmdbFile = function() {
    _scanCmdb = null;
    _updateCmdbHint();
};

window._updateCmdbHint = function() {
    const status = document.getElementById('scan-cmdb-status');
    const clear = document.getElementById('scan-cmdb-clear');
    const warn = document.getElementById('scan-cmdb-warn');
    const mode = document.querySelector('input[name="scan-mode"]:checked');
    if (status) {
        status.innerHTML = _scanCmdb
            ? `<span class="font-mono text-slate-300">${esc(_scanCmdb.name)}</span> · <span class="text-accent">${fmt(_scanCmdb.rows)} rows</span>`
            : 'Not attached — falls back to data/input/cmdb_export.csv';
    }
    if (clear) clear.classList.toggle('hidden', !_scanCmdb);
    if (warn) warn.classList.toggle('hidden', !!_scanCmdb || !mode || mode.value !== 'livecheck');
};

window.restoreArchive = async function(scanId) {
    if (!confirm(`Restore scan ${scanId}?\n\nThis will replace the current active scan data with this archived snapshot.`)) {
        return;
    }

    try {
        const res = await fetch(`/api/scans/${scanId}/restore`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Restore failed');

        const el = document.getElementById('page-content');
        if (el) pageScans(el);
    } catch (e) {
        alert('Error: ' + e.message);
    }
};

window.deleteArchive = async function(scanId) {
    if (!confirm(`Delete archived scan ${scanId}?\n\nThis action cannot be undone.`)) {
        return;
    }

    try {
        const res = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Delete failed');

        const el = document.getElementById('page-content');
        if (el) pageScans(el);
    } catch (e) {
        alert('Error: ' + e.message);
    }
};

window.exportScan = async function(scanId) {
    // Fetch (not a plain navigation) so the request carries the auth header.
    try {
        const res = await fetch(`/api/scans/${scanId}/export`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: res.statusText }));
            throw new Error(err.detail || `Export failed (${res.status})`);
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `assets_${scanId}.parquet`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert('Error: ' + e.message);
    }
};

window.importScan = async function() {
    const fileInput = document.getElementById('import-file');
    const statusEl = document.getElementById('import-status');
    const file = fileInput?.files?.[0];
    if (!file) return;

    const scanIdVal = document.getElementById('import-scan-id')?.value.trim() || '';
    const notesVal  = document.getElementById('import-notes')?.value.trim() || '';

    if (statusEl) {
        statusEl.textContent = 'Uploading…';
        statusEl.className = 'text-xs text-slate-400';
        statusEl.classList.remove('hidden');
    }

    const form = new FormData();
    form.append('file', file);
    if (scanIdVal) form.append('scan_id', scanIdVal);
    if (notesVal)  form.append('notes', notesVal);

    try {
        const res = await fetch('/api/scans/import', { method: 'POST', body: form });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Import failed');

        if (statusEl) {
            statusEl.textContent = `Imported as ${data.scan_id} (${data.stats?.total_assets ?? '?'} assets)`;
            statusEl.className = 'text-xs text-green-400';
        }
        fileInput.value = '';
        const el = document.getElementById('page-content');
        if (el) setTimeout(() => pageScans(el), 800);
    } catch (e) {
        if (statusEl) {
            statusEl.textContent = 'Error: ' + e.message;
            statusEl.className = 'text-xs text-red-400';
        }
    }
};

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------
function renderPagination(current, total, prefix) {
    const pages = [];
    const maxShow = 7;
    let start = Math.max(1, current - Math.floor(maxShow / 2));
    let end = Math.min(total, start + maxShow - 1);
    if (end - start < maxShow - 1) start = Math.max(1, end - maxShow + 1);

    return `
        <div class="flex items-center justify-between px-4 py-3 border-t border-surface-border">
            <span class="text-xs text-slate-500">Page ${current} of ${total}</span>
            <div class="flex gap-1">
                <button class="page-btn" onclick="${prefix}Page(${current - 1})" ${current <= 1 ? 'disabled' : ''}>Prev</button>
                ${Array.from({ length: end - start + 1 }, (_, i) => start + i).map(p =>
                    `<button class="page-btn ${p === current ? 'active' : ''}" onclick="${prefix}Page(${p})">${p}</button>`
                ).join('')}
                <button class="page-btn" onclick="${prefix}Page(${current + 1})" ${current >= total ? 'disabled' : ''}>Next</button>
            </div>
        </div>
    `;
}

// ---------------------------------------------------------------------------
// Page: Bug Bounty
// ---------------------------------------------------------------------------
const BOUNTY_TIER_COLORS = {
    S: { bg: 'rgba(239,68,68,0.15)', border: '#ef4444', text: '#fca5a5', label: 'Critical Priority' },
    A: { bg: 'rgba(249,115,22,0.15)', border: '#f97316', text: '#fdba74', label: 'High Priority' },
    B: { bg: 'rgba(234,179,8,0.15)', border: '#eab308', text: '#fde047', label: 'Medium Priority' },
    C: { bg: 'rgba(59,130,246,0.15)', border: '#3b82f6', text: '#93c5fd', label: 'Low Priority' },
    D: { bg: 'rgba(100,116,139,0.12)', border: '#54655E', text: '#93A69E', label: 'Background' },
};

// ---------------------------------------------------------------------------
// Page: AI Agent Discovery (AIMAP)
// ---------------------------------------------------------------------------
const AI_PROTOCOL_LABELS = {
    mcp: 'MCP', ollama: 'Ollama', openai_compat: 'OpenAI-Compatible',
    langserve: 'LangServe', gradio: 'Gradio', streamlit: 'Streamlit',
    comfyui: 'ComfyUI', textgen_webui: 'Text Gen WebUI',
    open_webui: 'Open WebUI', openclaw: 'OpenClaw',
};

const AI_PROTOCOL_COLORS = {
    mcp: '#8b5cf6', ollama: '#2FD9B0', openai_compat: '#10b981',
    langserve: '#f59e0b', gradio: '#ec4899', streamlit: '#ef4444',
    comfyui: '#3b82f6', textgen_webui: '#6366f1',
    open_webui: '#14b8a6', openclaw: '#f97316',
};

async function pageAimap(el) {
    let data;
    try {
        data = await api('/aimap');
    } catch (e) {
        el.innerHTML = `
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h1 class="text-2xl font-bold text-white">AI Agent Discovery</h1>
                    <p class="text-sm text-slate-500 mt-1">Exposed AI agents detected by AIMAP</p>
                </div>
            </div>
            ${renderEmptyState('No AIMAP data', 'Run the pipeline with the aimap stage enabled to discover exposed AI agents.')}
        `;
        return;
    }

    const items = data.items || [];
    const protocols = data.protocols || [];
    const severity = data.severity || [];
    const hosts = data.affected_hosts || [];
    const total = data.total || 0;

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">AI Agent Discovery</h1>
                <p class="text-sm text-slate-500 mt-1">${fmt(total)} exposed AI endpoints detected by AIMAP</p>
            </div>
        </div>

        <!-- KPI Cards -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="card kpi-card p-4" data-color="purple">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Total Findings</div>
                <div class="text-2xl font-bold text-white" data-counter="${total}">0</div>
                <div class="text-xs text-slate-500">${protocols.length} protocols detected</div>
            </div>
            <div class="card kpi-card p-4" data-color="cyan">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Affected Hosts</div>
                <div class="text-2xl font-bold text-white" data-counter="${hosts.length}">0</div>
                <div class="text-xs text-slate-500">unique FQDNs</div>
            </div>
            <div class="card kpi-card p-4" data-color="red">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Critical/High</div>
                <div class="text-2xl font-bold text-white" data-counter="${severity.filter(s => s.severity === 'critical' || s.severity === 'high').reduce((a,s) => a + s.count, 0)}">0</div>
                <div class="text-xs text-slate-500">high severity agents</div>
            </div>
            <div class="card kpi-card p-4" data-color="green">
                <div class="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Top Protocol</div>
                <div class="text-lg font-bold text-white">${protocols.length ? (AI_PROTOCOL_LABELS[protocols[0].protocol] || protocols[0].protocol) : 'N/A'}</div>
                <div class="text-xs text-slate-500">${protocols.length ? protocols[0].count + ' endpoints' : ''}</div>
            </div>
        </div>

        <!-- Charts -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            ${protocols.length ? `
                <div class="card p-5">
                    <h3 class="text-sm font-semibold text-slate-300 mb-4">AI Protocols Detected</h3>
                    <div class="chart-container" style="height: 260px;">
                        <canvas id="chart-aimap-protocols"></canvas>
                    </div>
                </div>
            ` : ''}
            ${severity.length ? `
                <div class="card p-5">
                    <h3 class="text-sm font-semibold text-slate-300 mb-4">Findings by Severity</h3>
                    <div class="chart-container" style="height: 260px;">
                        <canvas id="chart-aimap-severity"></canvas>
                    </div>
                </div>
            ` : ''}
        </div>

        <!-- Affected Hosts -->
        ${hosts.length ? `
            <div class="card p-5 mb-4">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Top Affected Hosts</h3>
                <div class="overflow-x-auto">
                    <table class="data-table">
                        <thead><tr><th>FQDN</th><th>AI Findings</th></tr></thead>
                        <tbody>
                            ${hosts.map(h => `
                                <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(h.fqdn)}'})">
                                    <td class="font-mono text-xs text-accent">${esc(h.fqdn)}</td>
                                    <td><span class="font-bold text-white">${fmt(h.finding_count)}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : ''}

        <!-- Findings Table -->
        <div class="card overflow-hidden">
            <div class="p-4 border-b border-surface-border">
                <h3 class="text-sm font-semibold text-slate-300">AI Agent Findings</h3>
            </div>
            <div class="overflow-x-auto" style="max-height: 500px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>FQDN</th>
                            <th>Finding</th>
                            <th>Template</th>
                            <th>Tags</th>
                            <th>Matched At</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${items.length ? items.map(f => {
                            const fTags = (f.tags || []).filter(Boolean);
                            return `
                            <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(f.fqdn)}'})">
                                <td>${severityBadge(f.severity)}</td>
                                <td class="font-mono text-xs text-accent">${esc(f.fqdn)}</td>
                                <td>${esc(f.finding_name)}</td>
                                <td class="font-mono text-xs text-slate-500">${esc(f.template_id)}</td>
                                <td class="text-xs">${fTags.map(t => `<span class="inline-block ${AI_PROTOCOL_LABELS[t] ? 'bg-purple-900/40 text-purple-300' : 'bg-slate-800 text-slate-300'} rounded px-1.5 py-0.5 mr-1 mb-0.5">${esc(AI_PROTOCOL_LABELS[t] || t)}</span>`).join('')}</td>
                                <td class="text-xs text-slate-400 max-w-[200px] truncate">${esc(f.matched_at)}</td>
                            </tr>`;
                        }).join('') : `<tr><td colspan="6">${renderEmptyState('No AI agent findings', 'Run the pipeline with --stage aimap to scan for exposed AI agents.')}</td></tr>`}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    // Animate counters
    requestAnimationFrame(() => {
        document.querySelectorAll('[data-counter]').forEach(el => {
            const raw = el.getAttribute('data-counter');
            const val = parseFloat(raw);
            if (!isNaN(val)) animateCounter(el, val);
        });
    });

    // Protocol chart
    if (protocols.length) {
        createChart('chart-aimap-protocols', {
            type: 'bar',
            data: {
                labels: protocols.map(p => AI_PROTOCOL_LABELS[p.protocol] || p.protocol),
                datasets: [{
                    data: protocols.map(p => p.count),
                    backgroundColor: protocols.map(p => AI_PROTOCOL_COLORS[p.protocol] || '#6b7280'),
                    borderRadius: 6,
                    barThickness: 32,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                indexAxis: 'y',
                plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
                scales: {
                    x: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A' } },
                    y: { grid: { display: false }, ticks: { color: '#93A69E', font: { weight: '600' } } },
                },
            },
        });
    }

    // Severity chart
    if (severity.length) {
        createChart('chart-aimap-severity', {
            type: 'doughnut',
            data: {
                labels: severity.map(s => capitalize(s.severity)),
                datasets: [{
                    data: severity.map(s => s.count),
                    backgroundColor: severity.map(s => SEVERITY_COLORS[s.severity] || '#6b7280'),
                    borderWidth: 0,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                cutout: '60%',
                plugins: {
                    ...CHART_DEFAULTS.plugins,
                    legend: {
                        position: 'right',
                        labels: { color: '#93A69E', padding: 16, usePointStyle: true, pointStyleWidth: 8 },
                    },
                },
            },
        });
    }
}

// ---------------------------------------------------------------------------
// Page: Cloud Assets
// ---------------------------------------------------------------------------
const PROVIDER_COLORS = {
    azure: { text: '#38bdf8', bg: '#38bdf815', border: '#38bdf830', label: 'Azure' },
    aws: { text: '#f97316', bg: '#f9731615', border: '#f9731630', label: 'AWS' },
    gcp: { text: '#34d399', bg: '#34d39915', border: '#34d39930', label: 'GCP' },
};

function providerBadge(provider) {
    const s = PROVIDER_COLORS[provider] || { text: '#93A69E', bg: '#93A69E15', border: '#93A69E30', label: provider };
    return `<span class="text-[10px] px-2 py-0.5 rounded font-medium" style="color:${s.text};background:${s.bg};border:1px solid ${s.border}">${esc(s.label)}</span>`;
}

function cloudRiskBadge(risk) {
    return severityBadge(risk);
}

async function pageCloud(el) {
    let data;
    try {
        data = await api('/cloud');
    } catch (e) {
        el.innerHTML = renderErrorState(e.message);
        return;
    }

    const items = data.items || [];
    const providers = data.providers || [];
    const summary = data.summary || [];
    const riskDist = data.risk_distribution || [];

    if (!items.length && !summary.length) {
        el.innerHTML = `
            <h1 class="text-2xl font-bold text-white mb-2">Cloud Assets</h1>
            <p class="text-sm text-slate-500 mb-6">Azure, AWS & GCP endpoint discovery</p>
            ${renderEmptyState('No cloud endpoints detected', 'Run the pipeline with cloud_enum stage to discover cloud assets')}
        `;
        return;
    }

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Cloud Assets</h1>
                <p class="text-sm text-slate-500 mt-1">Azure, AWS & GCP endpoint discovery</p>
            </div>
            <div class="text-right">
                <div class="text-xs text-slate-500">Total Endpoints</div>
                <div class="text-2xl font-bold text-cyan-400">${data.total_endpoints || 0}</div>
            </div>
        </div>

        <!-- KPI Cards -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            ${providers.map(p => `
                <div class="card p-4">
                    <div class="flex items-center gap-2 mb-2">
                        ${providerBadge(p.provider)}
                    </div>
                    <div class="text-2xl font-bold text-white">${fmt(p.host_count)}</div>
                    <div class="text-xs text-slate-500">${fmtPct(p.pct || 0)} of assets</div>
                </div>
            `).join('')}
        </div>

        <!-- Charts Row -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Provider Distribution</h3>
                <div class="chart-container" style="height: 240px;">
                    <canvas id="chart-cloud-providers"></canvas>
                </div>
            </div>
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Risk Distribution</h3>
                <div class="chart-container" style="height: 240px;">
                    <canvas id="chart-cloud-risk"></canvas>
                </div>
            </div>
        </div>

        <!-- Service Summary -->
        <div class="card p-5 mb-6">
            <h3 class="text-sm font-semibold text-slate-300 mb-4">Cloud Services Detected</h3>
            <div class="overflow-x-auto">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Provider</th>
                            <th>Service</th>
                            <th>Description</th>
                            <th>Risk</th>
                            <th>Endpoints</th>
                            <th>Hosts</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${summary.map(s => `
                            <tr>
                                <td>${providerBadge(s.provider)}</td>
                                <td class="font-mono text-xs text-slate-300">${esc(s.service)}</td>
                                <td class="text-slate-400 text-sm">${esc(s.service_label || s.service)}</td>
                                <td>${cloudRiskBadge(s.risk)}</td>
                                <td class="font-bold text-white">${fmt(s.count)}</td>
                                <td class="text-slate-400">${fmt(s.affected_hosts)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Filter Bar -->
        <div class="card p-4 mb-4">
            <div class="flex flex-wrap items-center gap-3">
                <div class="flex items-center gap-2">
                    ${ICONS.filter}
                    <span class="text-xs text-slate-500">Filter:</span>
                </div>
                <select id="cloud-provider-filter" class="bg-surface-card border border-surface-border rounded px-3 py-1.5 text-sm text-slate-300">
                    <option value="">All Providers</option>
                    <option value="azure">Azure</option>
                    <option value="aws">AWS</option>
                    <option value="gcp">GCP</option>
                </select>
                <select id="cloud-risk-filter" class="bg-surface-card border border-surface-border rounded px-3 py-1.5 text-sm text-slate-300">
                    <option value="">All Risk Levels</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <div class="relative flex-1 min-w-[200px]">
                    <input id="cloud-search" type="text" placeholder="Search endpoints..." class="w-full bg-surface-card border border-surface-border rounded px-3 py-1.5 text-sm text-slate-300 pl-8"/>
                    <div class="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500">${ICONS.search}</div>
                </div>
            </div>
        </div>

        <!-- All Endpoints Table -->
        <div class="card p-5">
            <h3 class="text-sm font-semibold text-slate-300 mb-4">All Cloud Endpoints (${items.length})</h3>
            <div class="overflow-x-auto">
                <table class="data-table" id="cloud-table">
                    <thead>
                        <tr>
                            <th>FQDN</th>
                            <th>Provider</th>
                            <th>Service</th>
                            <th>Risk</th>
                            <th>Resource</th>
                            <th>Cloud Hostname</th>
                            <th>Signals</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${items.map(i => `
                            <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(i.fqdn)}'})">
                                <td class="font-mono text-xs text-accent">${esc(i.fqdn)}</td>
                                <td>${providerBadge(i.provider)}</td>
                                <td class="text-sm text-slate-300">${esc(i.service_label || i.service)}</td>
                                <td>${cloudRiskBadge(i.risk)}</td>
                                <td class="font-mono text-xs text-slate-400">${esc(i.resource_name || '-')}</td>
                                <td class="font-mono text-xs text-slate-500">${esc(i.hostname || '-')}</td>
                                <td class="text-xs text-slate-500">${(i.signals || []).map(s => `<span class="inline-block bg-surface-card border border-surface-border rounded px-1.5 py-0.5 mr-1 mb-1">${esc(s)}</span>`).join('')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    // Charts
    if (providers.length) {
        const provPalette = providers.map(p => {
            const c = PROVIDER_COLORS[p.provider];
            return c ? c.text : '#93A69E';
        });
        createChart('chart-cloud-providers', {
            type: 'doughnut',
            data: {
                labels: providers.map(p => (PROVIDER_COLORS[p.provider] || {}).label || p.provider),
                datasets: [{
                    data: providers.map(p => p.host_count),
                    backgroundColor: provPalette,
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                cutout: '65%',
                plugins: {
                    ...CHART_DEFAULTS.plugins,
                    legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
                },
            },
        });
    }

    if (riskDist.length) {
        createChart('chart-cloud-risk', {
            type: 'bar',
            data: {
                labels: riskDist.map(r => capitalize(r.risk)),
                datasets: [{
                    label: 'Endpoints',
                    data: riskDist.map(r => r.count),
                    backgroundColor: riskDist.map(r => SEVERITY_COLORS[r.risk] || '#6b7280'),
                    borderWidth: 0,
                    borderRadius: 4,
                }],
            },
            options: {
                ...CHART_DEFAULTS,
                plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#93A69E', font: { size: 11 } } },
                    y: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', font: { size: 10 } } },
                },
            },
        });
    }

    // Filter handlers
    const filterCloud = async () => {
        const provider = document.getElementById('cloud-provider-filter').value;
        const risk = document.getElementById('cloud-risk-filter').value;
        const search = document.getElementById('cloud-search').value;
        const filtered = await api('/cloud', { provider, risk, search });
        const tbody = document.querySelector('#cloud-table tbody');
        if (tbody) {
            tbody.innerHTML = (filtered.items || []).map(i => `
                <tr class="clickable" onclick="navigateTo('detail', {id: '${esc(i.fqdn)}'})">
                    <td class="font-mono text-xs text-accent">${esc(i.fqdn)}</td>
                    <td>${providerBadge(i.provider)}</td>
                    <td class="text-sm text-slate-300">${esc(i.service_label || i.service)}</td>
                    <td>${cloudRiskBadge(i.risk)}</td>
                    <td class="font-mono text-xs text-slate-400">${esc(i.resource_name || '-')}</td>
                    <td class="font-mono text-xs text-slate-500">${esc(i.hostname || '-')}</td>
                    <td class="text-xs text-slate-500">${(i.signals || []).map(s => `<span class="inline-block bg-surface-card border border-surface-border rounded px-1.5 py-0.5 mr-1 mb-1">${esc(s)}</span>`).join('')}</td>
                </tr>
            `).join('');
        }
    };

    document.getElementById('cloud-provider-filter')?.addEventListener('change', filterCloud);
    document.getElementById('cloud-risk-filter')?.addEventListener('change', filterCloud);
    const searchInput = document.getElementById('cloud-search');
    if (searchInput) {
        let debounceTimer;
        searchInput.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(filterCloud, 300);
        });
    }
}

// ---------------------------------------------------------------------------
// Page: Bug Bounty
// ---------------------------------------------------------------------------
async function pageBounty(el) {
    let data;
    try {
        data = await api('/bounty');
    } catch (e) {
        el.innerHTML = renderErrorState(e.message);
        return;
    }

    if (!data.available) {
        el.innerHTML = `
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h1 class="text-2xl font-bold text-white">Bug Bounty Prep</h1>
                    <p class="text-sm text-slate-500 mt-1">Ranked target list for bug bounty programs</p>
                </div>
            </div>
            <div class="card p-10 text-center">
                <div class="text-slate-600 mb-4 flex justify-center">${ICONS.bounty}</div>
                <p class="text-slate-300 font-medium mb-2">No bounty data available</p>
                <p class="text-sm text-slate-500 mb-4">Run the pipeline in bounty mode to generate scored targets.</p>
                <a href="#/scans" class="btn-primary inline-flex items-center gap-2">
                    ${ICONS.newScan} Go to New Scan
                </a>
            </div>
        `;
        return;
    }

    const items = data.items || [];
    const summary = data.summary || [];
    const tierOrder = ['S', 'A', 'B', 'C', 'D'];

    const tierCounts = {};
    tierOrder.forEach(t => { tierCounts[t] = 0; });
    summary.forEach(s => { if (s.tier) tierCounts[s.tier] = s.count || 0; });

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Bug Bounty Prep</h1>
                <p class="text-sm text-slate-500 mt-1">${fmt(items.length)} targets scored — sorted by priority</p>
            </div>
            <div class="flex gap-2">
                <button onclick="exportBounty('csv')" class="btn-secondary text-xs flex items-center gap-1.5">
                    ${ICONS.download} CSV
                </button>
                <button onclick="exportBounty('json')" class="btn-secondary text-xs flex items-center gap-1.5">
                    ${ICONS.download} JSON
                </button>
            </div>
        </div>

        <!-- Tier distribution -->
        <div class="grid grid-cols-5 gap-3 mb-6">
            ${tierOrder.map(tier => {
                const c = BOUNTY_TIER_COLORS[tier] || BOUNTY_TIER_COLORS.D;
                const row = summary.find(s => s.tier === tier) || {};
                return `
                    <div class="card p-4 text-center" style="border-color: ${c.border}; background: ${c.bg}">
                        <div class="text-3xl font-bold" style="color: ${c.text}">${tier}</div>
                        <div class="text-xl font-bold text-white mt-1">${fmt(row.count || 0)}</div>
                        <div class="text-[10px] text-slate-500 uppercase tracking-wider mt-1">${c.label}</div>
                        ${row.avg_score != null ? `<div class="text-[10px] text-slate-600 mt-0.5">avg ${row.avg_score}</div>` : ''}
                    </div>
                `;
            }).join('')}
        </div>

        <!-- Target table -->
        <div class="card overflow-hidden">
            <div class="flex items-center justify-between px-5 py-3 border-b border-surface-border">
                <h3 class="text-sm font-semibold text-slate-300">Ranked Targets</h3>
                <input id="bounty-search" type="text" placeholder="Filter targets…"
                       oninput="filterBountyTable(this.value)"
                       class="text-xs bg-[#0B100E] border border-slate-700 rounded px-2 py-1 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-accent w-52" />
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead>
                        <tr class="border-b border-surface-border text-slate-500 uppercase tracking-wider">
                            <th class="px-4 py-2 text-left">Tier</th>
                            <th class="px-4 py-2 text-left">Score</th>
                            <th class="px-4 py-2 text-left">FQDN</th>
                            <th class="px-4 py-2 text-left">Top Signal</th>
                            <th class="px-4 py-2 text-right">Ports</th>
                            <th class="px-4 py-2 text-right">Findings</th>
                            <th class="px-4 py-2 text-center">Auth</th>
                            <th class="px-4 py-2 text-center">CDN</th>
                        </tr>
                    </thead>
                    <tbody id="bounty-table-body">
                        ${_renderBountyRows(items)}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    window._bountyItems = items;
}

function _tierBadge(tier) {
    const c = BOUNTY_TIER_COLORS[tier] || BOUNTY_TIER_COLORS.D;
    return `<span class="font-bold text-sm px-2 py-0.5 rounded" style="color:${c.text};background:${c.bg};border:1px solid ${c.border}">${esc(tier)}</span>`;
}

function _renderBountyRows(items) {
    if (!items.length) return `<tr><td colspan="8" class="text-center py-8 text-slate-500">No targets</td></tr>`;
    window._bountyRowData = items;
    return items.map((item, idx) => {
        const highlights = item.highlights || [];
        const topSignal = highlights[0] || '-';
        const ports = (item.open_ports || []).length;
        const cdn = item.behind_cdn;
        return `
            <tr class="border-b border-surface-border hover:bg-white/[0.02] transition-colors cursor-pointer"
                onclick="_expandBountyRow(this, ${idx})">
                <td class="px-4 py-2.5">${_tierBadge(item.tier)}</td>
                <td class="px-4 py-2.5 font-bold text-white">${item.bounty_score}</td>
                <td class="px-4 py-2.5 font-mono text-slate-200">${esc(item.fqdn)}</td>
                <td class="px-4 py-2.5 text-slate-400 max-w-[280px] truncate" title="${esc(topSignal)}">${esc(topSignal)}</td>
                <td class="px-4 py-2.5 text-right text-slate-300">${fmt(ports)}</td>
                <td class="px-4 py-2.5 text-right ${item.critical_findings > 0 ? 'text-red-400' : 'text-slate-300'}">${fmt(item.nuclei_findings || 0)}</td>
                <td class="px-4 py-2.5 text-center">${item.has_auth ? '<span class="text-green-400">✓</span>' : '<span class="text-slate-600">-</span>'}</td>
                <td class="px-4 py-2.5 text-center">${cdn ? '<span class="text-slate-400">CDN</span>' : '<span class="text-yellow-400">Direct</span>'}</td>
            </tr>
        `;
    }).join('');
}

window._expandBountyRow = function(tr, idx) {
    const existingDetail = tr.nextElementSibling;
    if (existingDetail && existingDetail.classList.contains('bounty-detail-row')) {
        existingDetail.remove();
        return;
    }
    const item = (window._bountyRowData || [])[idx];
    if (!item) return;

    const detail = document.createElement('tr');
    detail.className = 'bounty-detail-row';
    const sb = {
        attack_surface: item.score_attack_surface,
        technology: item.score_technology,
        security_posture: item.score_security_posture,
        criticality: item.score_criticality,
    };
    const recs = item.recommended_focus || [];
    const highlights = item.highlights || [];
    const techs = item.technologies || [];

    detail.innerHTML = `
        <td colspan="8" class="px-6 py-4 bg-[#0B100E] border-b border-surface-border">
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div>
                    <div class="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Score Breakdown</div>
                    ${[['Attack Surface', sb.attack_surface, 25],['Technology', sb.technology, 25],
                       ['Security Posture', sb.security_posture, 25],['Criticality', sb.criticality, 25]]
                      .map(([label, val, max]) => `
                        <div class="mb-1.5">
                            <div class="flex justify-between text-xs mb-0.5">
                                <span class="text-slate-400">${esc(label)}</span>
                                <span class="text-slate-300">${val || 0}/${max}</span>
                            </div>
                            <div class="h-1.5 rounded bg-slate-800">
                                <div class="h-full rounded bg-accent" style="width:${Math.round((val||0)/max*100)}%"></div>
                            </div>
                        </div>
                    `).join('')}
                </div>
                <div>
                    <div class="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Signals Detected</div>
                    <ul class="space-y-1">
                        ${highlights.map(h => `<li class="text-xs text-slate-300 flex gap-1.5"><span class="text-accent mt-0.5">›</span>${esc(h)}</li>`).join('')}
                    </ul>
                    ${techs.length ? `<div class="mt-2 flex flex-wrap gap-1">${techs.slice(0,8).map(t => `<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">${esc(t)}</span>`).join('')}</div>` : ''}
                </div>
                <div>
                    <div class="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Recommended Focus</div>
                    <ol class="space-y-1.5 list-decimal list-inside">
                        ${recs.map(r => `<li class="text-xs text-slate-300">${esc(r)}</li>`).join('') || '<li class="text-xs text-slate-500">No specific recommendations</li>'}
                    </ol>
                    <a href="#/detail/${encodeURIComponent(item.fqdn)}" class="inline-block mt-3 text-xs text-accent hover:underline">
                        View full asset details ${ICONS.chevronRight}
                    </a>
                </div>
            </div>
        </td>
    `;
    tr.insertAdjacentElement('afterend', detail);
};

window.filterBountyTable = function(q) {
    const items = window._bountyItems || [];
    const filtered = q
        ? items.filter(i => (i.fqdn || '').toLowerCase().includes(q.toLowerCase()))
        : items;
    const tbody = document.getElementById('bounty-table-body');
    if (tbody) tbody.innerHTML = _renderBountyRows(filtered);
};

window.exportBounty = async function(fmt) {
    try {
        const res = await fetch(`/api/bounty/export?format=${fmt}`);
        if (!res.ok) { alert('Export failed'); return; }
        const data = await res.json();
        if (fmt === 'csv') {
            const blob = new Blob([data.csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'bounty_report.csv'; a.click();
            URL.revokeObjectURL(url);
        } else {
            const blob = new Blob([JSON.stringify(data.items || data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'bounty_report.json'; a.click();
            URL.revokeObjectURL(url);
        }
    } catch (e) { alert('Export error: ' + e.message); }
};

// ---------------------------------------------------------------------------
// Page: Archive Viewer
// ---------------------------------------------------------------------------
let _archiveTabState = { page: 1, severity: '' };

async function pageArchive(el, scanId) {
    if (!scanId) { navigateTo('scans'); return; }

    const [meta, data] = await Promise.all([
        api(`/scans/${encodeURIComponent(scanId)}`),
        api(`/scans/${encodeURIComponent(scanId)}/overview`),
    ]);

    _archiveTabState = { page: 1, severity: '' };

    const s = data.scan || {};
    const sev = data.severity_map || {};
    const tls = data.tls_health || {};
    const totalAssets = s.total_assets || 0;
    const shadowIt = s.shadow_it || 0;
    const coveragePct = totalAssets > 0 ? ((s.in_cmdb || 0) / totalAssets * 100) : 0;

    el.innerHTML = `
        <div class="mb-5 flex items-center gap-3 px-4 py-3 rounded-xl border border-amber-500/30 bg-amber-500/5">
            <span class="text-amber-400 shrink-0">${ICONS.archive}</span>
            <div class="flex-1 min-w-0">
                <span class="text-sm font-semibold text-amber-300">Archived Scan</span>
                <span class="font-mono text-xs text-slate-300 ml-2">${esc(scanId)}</span>
                ${meta.archived_at ? `<span class="text-xs text-slate-500 ml-2">— archived ${fmtDate(meta.archived_at)}</span>` : ''}
            </div>
            <div class="flex items-center gap-2 shrink-0">
                <button onclick="exportScan('${esc(scanId)}')" class="btn-secondary text-xs py-1 px-3 flex items-center gap-1.5">
                    ${ICONS.download} Export
                </button>
                <a href="#/compare/${esc(scanId)}" class="btn-secondary text-xs py-1 px-3">
                    Compare
                </a>
                <a href="#/scans" class="btn-secondary text-xs py-1 px-3 flex items-center gap-1.5">
                    ${ICONS.arrowLeft} Back
                </a>
            </div>
        </div>

        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">Attack Surface Overview</h1>
                <p class="text-sm text-slate-500 mt-1">
                    Scan: ${esc(s.scan_id || scanId)}
                    <span class="text-amber-500/70 ml-1">(read-only)</span>
                </p>
            </div>
            <div class="flex items-center gap-3">
                <div class="text-right">
                    <div class="text-xs text-slate-500">Risk Score</div>
                    <div class="text-2xl font-bold ${riskColor(data.risk_score)}">${data.risk_score}</div>
                </div>
                ${renderRiskGauge(data.risk_score)}
            </div>
        </div>

        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-6">
            ${kpiCard('Total Assets', totalAssets, 'Discovered FQDNs', 'cyan', 'arc-total')}
            ${kpiCard('Web Assets', s.web_assets, 'HTTP/HTTPS services', 'blue', 'arc-web')}
            ${kpiCard('Shadow IT', shadowIt, totalAssets ? fmtPct(shadowIt / totalAssets * 100) + ' of total' : '', 'red', 'arc-shadow')}
            ${kpiCard('Findings', s.total_findings, (sev.critical || 0) + ' critical', 'orange', 'arc-findings')}
            ${kpiCard('TLS Issues', tls.issues_total, (tls.expired || 0) + ' expired', 'yellow', 'arc-tls')}
            ${kpiCard('CMDB Coverage', fmtPct(coveragePct), (s.in_cmdb || 0) + ' matched', 'green', 'arc-coverage', true)}
            ${kpiCard('Services', s.total_services, (s.assets_with_services || 0) + ' hosts', 'purple', 'arc-services')}
        </div>

        <div class="flex items-center gap-0 mb-5 border-b border-surface-border">
            ${['overview', 'assets', 'findings', 'tls', 'takeovers'].map((tab, i) => `
                <button class="archive-tab px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px
                    ${i === 0 ? 'text-white border-accent' : 'text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-600'}"
                    data-tab="${tab}"
                    onclick="setArchiveTab('${esc(scanId)}', '${tab}')">
                    ${capitalize(tab)}
                </button>
            `).join('')}
        </div>

        <div id="archive-tab-content"></div>
    `;

    requestAnimationFrame(() => {
        document.querySelectorAll('[data-counter]').forEach(el => {
            const val = parseFloat(el.getAttribute('data-counter'));
            if (!isNaN(val)) animateCounter(el, val);
        });
    });

    const tabContent = document.getElementById('archive-tab-content');
    if (tabContent) _renderArchiveOverviewTab(tabContent, data);
}

function _renderArchiveOverviewTab(el, data) {
    el.innerHTML = `
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Findings by Severity</h3>
                <div class="chart-container" style="height: 240px;"><canvas id="arc-chart-severity"></canvas></div>
            </div>
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">CMDB Coverage</h3>
                <div class="chart-container" style="height: 240px;"><canvas id="arc-chart-cmdb"></canvas></div>
            </div>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Top Technologies</h3>
                <div class="chart-container" style="height: 280px;"><canvas id="arc-chart-tech"></canvas></div>
            </div>
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Port Distribution</h3>
                <div class="chart-container" style="height: 280px;"><canvas id="arc-chart-ports"></canvas></div>
            </div>
        </div>
    `;
    initArchiveOverviewCharts(data);
}

function initArchiveOverviewCharts(data) {
    const sev = data.findings_by_severity || [];
    if (sev.length) {
        createChart('arc-chart-severity', {
            type: 'doughnut',
            data: {
                labels: sev.map(s => capitalize(s.severity)),
                datasets: [{ data: sev.map(s => s.count), backgroundColor: sev.map(s => SEVERITY_COLORS[s.severity] || '#6b7280'), borderWidth: 0, hoverOffset: 6 }],
            },
            options: { ...CHART_DEFAULTS, cutout: '65%', plugins: { ...CHART_DEFAULTS.plugins, legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' } } },
        });
    }
    const scan = data.scan || {};
    const inCmdb = scan.in_cmdb || 0, shadowItV = scan.shadow_it || 0, staleCi = scan.stale_ci || 0;
    const other = Math.max(0, (scan.not_in_cmdb || 0) - shadowItV);
    if (inCmdb || shadowItV || staleCi || other) {
        createChart('arc-chart-cmdb', {
            type: 'doughnut',
            data: {
                labels: ['In CMDB', 'Shadow IT', 'Stale CI', 'Other Gaps'],
                datasets: [{ data: [inCmdb, shadowItV, staleCi, other], backgroundColor: ['#10b981', '#ef4444', '#eab308', '#f97316'], borderWidth: 0, hoverOffset: 6 }],
            },
            options: { ...CHART_DEFAULTS, cutout: '65%', plugins: { ...CHART_DEFAULTS.plugins, legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' } } },
        });
    }
    const tech = data.top_technologies || [];
    if (tech.length) {
        createChart('arc-chart-tech', {
            type: 'bar',
            data: { labels: tech.map(t => t.name), datasets: [{ data: tech.map(t => t.count), backgroundColor: 'rgba(47,217,176,0.6)', borderColor: '#2FD9B0', borderWidth: 1, borderRadius: 4, barThickness: 18 }] },
            options: { ...CHART_DEFAULTS, indexAxis: 'y', plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } }, scales: { x: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', font: { size: 10 } } }, y: { grid: { display: false }, ticks: { color: '#93A69E', font: { family: 'IBM Plex Mono', size: 11 } } } } },
        });
    }
    const ports = data.port_distribution || [];
    if (ports.length) {
        createChart('arc-chart-ports', {
            type: 'bar',
            data: { labels: ports.map(p => ':' + p.port), datasets: [{ data: ports.map(p => p.count), backgroundColor: 'rgba(59,130,246,0.6)', borderColor: '#3b82f6', borderWidth: 1, borderRadius: 4 }] },
            options: { ...CHART_DEFAULTS, plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { color: '#93A69E', font: { family: 'IBM Plex Mono', size: 10 } } }, y: { grid: { color: '#1F2B26' }, ticks: { color: '#6E827A', font: { size: 10 } } } } },
        });
    }
}

window.setArchiveTab = async function(scanId, tab, page) {
    document.querySelectorAll('.archive-tab').forEach(t => {
        const active = t.dataset.tab === tab;
        t.className = `archive-tab px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
            active ? 'text-white border-accent' : 'text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-600'
        }`;
    });

    const content = document.getElementById('archive-tab-content');
    if (!content) return;
    content.innerHTML = renderLoadingState();

    try {
        if (tab === 'overview') {
            const data = await api(`/scans/${scanId}/overview`);
            _renderArchiveOverviewTab(content, data);

        } else if (tab === 'assets') {
            _archiveTabState.page = page || 1;
            const data = await api(`/scans/${scanId}/assets`, { page: _archiveTabState.page, limit: 50 });
            content.innerHTML = `
                <div class="card overflow-hidden">
                    <div class="overflow-x-auto">
                        <table class="data-table">
                            <thead><tr>
                                <th>FQDN</th><th>Ports</th><th>Web</th><th>Findings</th><th>CDN</th><th>Gap</th>
                            </tr></thead>
                            <tbody>
                                ${data.items.length ? data.items.map(a => `
                                    <tr>
                                        <td class="font-mono text-xs text-accent">${esc(a.fqdn)}</td>
                                        <td>${a.port_count || 0}</td>
                                        <td>${a.web_entry_count || 0}</td>
                                        <td>${a.finding_count ? `<span class="text-orange-400 font-medium">${a.finding_count}</span>` : '<span class="text-slate-600">0</span>'}</td>
                                        <td class="text-slate-400 text-xs">${esc(a.cdn || '-')}</td>
                                        <td>${gapBadge(a.gap_type)}</td>
                                    </tr>
                                `).join('') : `<tr><td colspan="6">${renderEmptyState('No assets', '')}</td></tr>`}
                            </tbody>
                        </table>
                    </div>
                    ${data.pages > 1 ? `
                        <div class="flex items-center justify-between px-4 py-3 border-t border-surface-border">
                            <span class="text-xs text-slate-500">${fmt(data.total)} total · page ${data.page} of ${data.pages}</span>
                            <div class="flex gap-1">
                                <button class="page-btn" onclick="setArchiveTab('${esc(scanId)}', 'assets', ${data.page - 1})" ${data.page <= 1 ? 'disabled' : ''}>Prev</button>
                                <button class="page-btn" onclick="setArchiveTab('${esc(scanId)}', 'assets', ${data.page + 1})" ${data.page >= data.pages ? 'disabled' : ''}>Next</button>
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;

        } else if (tab === 'findings') {
            const data = await api(`/scans/${scanId}/findings`, { severity: _archiveTabState.severity || '', limit: 200 });
            content.innerHTML = `
                <div class="flex flex-wrap gap-2 mb-4">
                    ${['', 'critical', 'high', 'medium', 'low', 'info'].map(s => `
                        <button class="btn-secondary text-xs py-1 px-3 ${_archiveTabState.severity === s ? 'ring-1 ring-accent text-accent' : ''}"
                                onclick="_setArchiveFindingsSeverity('${esc(scanId)}', '${s}')">
                            ${s ? capitalize(s) : 'All'}
                        </button>
                    `).join('')}
                </div>
                <div class="card overflow-hidden">
                    <div class="overflow-x-auto">
                        <table class="data-table">
                            <thead><tr>
                                <th>Severity</th><th>FQDN</th><th>Finding</th><th>Template</th><th>Matched At</th>
                            </tr></thead>
                            <tbody>
                                ${data.items.length ? data.items.map(f => `
                                    <tr>
                                        <td>${severityBadge(f.severity)}</td>
                                        <td class="font-mono text-xs text-accent">${esc(f.fqdn)}</td>
                                        <td>${esc(f.finding_name)}</td>
                                        <td class="text-slate-500 font-mono text-xs">${esc(f.template_id)}</td>
                                        <td class="text-slate-400 text-xs">${esc(f.matched_at)}</td>
                                    </tr>
                                `).join('') : `<tr><td colspan="5">${renderEmptyState('No findings', '')}</td></tr>`}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

        } else if (tab === 'tls') {
            const data = await api(`/scans/${scanId}/tls`, { limit: 200 });
            const sm = data.summary || {};
            content.innerHTML = `
                <div class="grid grid-cols-3 md:grid-cols-6 gap-3 mb-4">
                    ${kpiCard('Total Issues', sm.total, '', 'red', 'arc-tls-total')}
                    ${kpiCard('Expired', sm.expired, '', 'red', 'arc-tls-exp')}
                    ${kpiCard('Self-Signed', sm.self_signed, '', 'orange', 'arc-tls-ss')}
                    ${kpiCard('Expiring <30d', sm.expiring_30d, '', 'yellow', 'arc-tls-30d')}
                    ${kpiCard('Mismatched', sm.mismatched, '', 'purple', 'arc-tls-mm')}
                    ${kpiCard('Revoked/Untrusted', (sm.revoked || 0) + (sm.untrusted || 0), '', 'red', 'arc-tls-rv')}
                </div>
                <div class="card overflow-hidden">
                    <div class="overflow-x-auto">
                        <table class="data-table">
                            <thead><tr>
                                <th>FQDN</th><th>Port</th><th>Issuer</th><th>Expires</th><th>Issues</th>
                            </tr></thead>
                            <tbody>
                                ${data.items.length ? data.items.map(t => `
                                    <tr>
                                        <td class="font-mono text-xs text-accent">${esc(t.fqdn)}</td>
                                        <td>${t.port}</td>
                                        <td class="text-slate-400 text-xs truncate max-w-[160px]">${esc(t.issuer || '-')}</td>
                                        <td class="text-xs ${(t.days_to_expiry || 999) < 30 ? 'text-yellow-400' : 'text-slate-400'}">${t.not_after ? fmtDate(t.not_after) : '-'}</td>
                                        <td class="text-xs space-x-1">
                                            ${t.expired ? '<span class="badge badge-critical">Expired</span>' : ''}
                                            ${t.self_signed ? '<span class="badge badge-high">Self-signed</span>' : ''}
                                            ${t.mismatched ? '<span class="badge badge-medium">Mismatch</span>' : ''}
                                        </td>
                                    </tr>
                                `).join('') : `<tr><td colspan="5">${renderEmptyState('No TLS issues', '')}</td></tr>`}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
            requestAnimationFrame(() => {
                document.querySelectorAll('[data-counter]').forEach(el => {
                    const val = parseFloat(el.getAttribute('data-counter'));
                    if (!isNaN(val)) animateCounter(el, val);
                });
            });

        } else if (tab === 'takeovers') {
            const data = await api(`/scans/${scanId}/takeovers`, { limit: 200 });
            content.innerHTML = `
                <div class="card overflow-hidden">
                    <div class="overflow-x-auto">
                        <table class="data-table">
                            <thead><tr>
                                <th>FQDN</th><th>Service</th><th>Status</th><th>Confidence</th><th>CNAME</th>
                            </tr></thead>
                            <tbody>
                                ${data.items.length ? data.items.map(t => `
                                    <tr>
                                        <td class="font-mono text-xs text-accent">${esc(t.fqdn)}</td>
                                        <td class="text-slate-400 text-xs">${esc(t.service || '-')}</td>
                                        <td><span class="badge badge-${t.status === 'confirmed' ? 'critical' : t.status === 'unverified' ? 'medium' : 'low'}">${esc(t.status)}</span></td>
                                        <td class="text-xs text-slate-400">${esc(t.confidence || '-')}</td>
                                        <td class="font-mono text-xs text-slate-500 truncate max-w-[200px]">${esc(t.stored_cname || '-')}</td>
                                    </tr>
                                `).join('') : `<tr><td colspan="5">${renderEmptyState('No takeover candidates', '')}</td></tr>`}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }
    } catch (e) {
        content.innerHTML = renderErrorState(e.message);
    }
};

window._setArchiveFindingsSeverity = function(scanId, severity) {
    _archiveTabState.severity = severity;
    setArchiveTab(scanId, 'findings');
};

// ---------------------------------------------------------------------------
// Page: Scan Comparison
// ---------------------------------------------------------------------------

async function pageCompare(el, scanA, scanB) {
    if (!scanA) { navigateTo('scans'); return; }

    // No scanB yet — show the scan picker
    if (!scanB) {
        await _pageComparePicker(el, scanA);
        return;
    }

    const data = await api(`/compare/${encodeURIComponent(scanA)}/${encodeURIComponent(scanB)}`);
    const riskDelta = data.risk_score.delta;
    const riskDeltaClass = riskDelta > 0 ? 'text-red-400' : riskDelta < 0 ? 'text-green-400' : 'text-slate-500';

    el.innerHTML = `
        <div class="flex items-center gap-3 mb-6">
            <button onclick="history.back()" class="btn-secondary text-xs py-1 px-3 flex items-center gap-1.5">
                ${ICONS.arrowLeft} Back
            </button>
            <div>
                <h1 class="text-2xl font-bold text-white">Scan Comparison</h1>
                <p class="text-sm text-slate-500 mt-1">Changes from baseline to current</p>
            </div>
        </div>

        <!-- Scan pair header -->
        <div class="card p-5 mb-5">
            <div class="grid grid-cols-5 gap-4 items-center">
                <div class="col-span-2 text-center p-3 rounded-xl bg-[#0B100E]">
                    <div class="text-[10px] text-slate-500 uppercase tracking-widest mb-1">Baseline (A)</div>
                    <div class="font-mono text-sm font-semibold text-slate-200">${esc(scanA === 'current' ? 'Current Active' : scanA)}</div>
                    <div class="text-xs text-slate-500 mt-1">${fmt(data.scan_a.total_assets)} assets</div>
                </div>
                <div class="text-center space-y-2">
                    <div class="text-slate-600 text-xl">→</div>
                    <button onclick="navigateTo('compare', {id: '${esc(scanB)}', id2: '${esc(scanA)}'})"
                            class="btn-secondary text-xs py-1 px-2 block mx-auto" title="Swap A and B">
                        ⇄ Swap
                    </button>
                    <a href="#/compare/${esc(scanA)}" class="btn-secondary text-xs py-1 px-2 block mx-auto">Change B</a>
                </div>
                <div class="col-span-2 text-center p-3 rounded-xl bg-[#0B100E]">
                    <div class="text-[10px] text-slate-500 uppercase tracking-widest mb-1">Current (B)</div>
                    <div class="font-mono text-sm font-semibold text-accent">${esc(scanB === 'current' ? 'Current Active' : scanB)}</div>
                    <div class="text-xs text-slate-500 mt-1">${fmt(data.scan_b.total_assets)} assets</div>
                </div>
            </div>
        </div>

        <!-- Risk score delta -->
        <div class="card p-5 mb-5">
            <h3 class="text-sm font-semibold text-slate-300 mb-5">Risk Score</h3>
            <div class="grid grid-cols-5 gap-4 items-center">
                <div class="col-span-2 flex items-center justify-center gap-5">
                    ${renderRiskGauge(data.risk_score.a)}
                    <div class="text-center">
                        <div class="text-3xl font-bold ${riskColor(data.risk_score.a)}">${data.risk_score.a}</div>
                        <div class="text-xs text-slate-500 mt-1">Baseline</div>
                    </div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold ${riskDeltaClass}">
                        ${riskDelta > 0 ? '+' : ''}${riskDelta}
                    </div>
                    <div class="text-[10px] text-slate-500 mt-1 uppercase tracking-wider">
                        ${riskDelta > 0 ? 'Higher risk' : riskDelta < 0 ? 'Lower risk' : 'Unchanged'}
                    </div>
                </div>
                <div class="col-span-2 flex items-center justify-center gap-5">
                    ${renderRiskGauge(data.risk_score.b)}
                    <div class="text-center">
                        <div class="text-3xl font-bold ${riskColor(data.risk_score.b)}">${data.risk_score.b}</div>
                        <div class="text-xs text-slate-500 mt-1">Current</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- KPI table -->
        <div class="card p-5 mb-5">
            <h3 class="text-sm font-semibold text-slate-300 mb-4">Metrics</h3>
            <div class="overflow-x-auto">
                <table class="data-table">
                    <thead><tr>
                        <th>Metric</th>
                        <th>Baseline (A)</th>
                        <th>Current (B)</th>
                        <th>Change</th>
                    </tr></thead>
                    <tbody>
                        ${_kpiRow('Total Assets',    data.kpis.total_assets,    false)}
                        ${_kpiRow('Web Assets',      data.kpis.web_assets,      false)}
                        ${_kpiRow('Total Findings',  data.kpis.total_findings,  true)}
                        ${_kpiRow('TLS Issues',      data.kpis.tls_issues,      true)}
                        ${_kpiRow('Shadow IT',       data.kpis.shadow_it,       true)}
                        ${_kpiRow('Stale CI',        data.kpis.stale_ci,        true)}
                        ${_kpiRow('In CMDB',         data.kpis.in_cmdb,         false)}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Asset changes -->
        <div class="card p-5 mb-5">
            <h3 class="text-sm font-semibold text-slate-300 mb-4">Asset Changes</h3>
            <div class="flex gap-1.5 mb-4">
                ${_compareTabBtn('cmp-asset', 'new',     'New',     data.totals?.new_assets     ?? data.new_assets.length,     true)}
                ${_compareTabBtn('cmp-asset', 'removed', 'Removed', data.totals?.removed_assets ?? data.removed_assets.length, false)}
                ${_compareTabBtn('cmp-asset', 'changed', 'Changed', data.totals?.changed_assets ?? data.changed_assets.length, false)}
            </div>
            <div id="cmp-assets-content">${_newAssetsTable(data.new_assets)}</div>
            <div id="cmp-assets-notice" class="text-xs text-slate-500 mt-2">${
                data.new_assets.length < (data.totals?.new_assets ?? 0)
                    ? `Showing ${data.new_assets.length} of ${data.totals.new_assets} new assets — use <code>?limit=N</code> to load more`
                    : ''
            }</div>
        </div>

        <!-- Finding changes -->
        <div class="card p-5">
            <h3 class="text-sm font-semibold text-slate-300 mb-4">Finding Changes</h3>
            <div class="flex gap-1.5 mb-4">
                ${_compareTabBtn('cmp-finding', 'new',      'New',      data.totals?.new_findings      ?? data.new_findings.length,      true)}
                ${_compareTabBtn('cmp-finding', 'resolved', 'Resolved', data.totals?.resolved_findings ?? data.resolved_findings.length, false)}
            </div>
            <div id="cmp-findings-content">${_findingsTable(data.new_findings)}</div>
            <div id="cmp-findings-notice" class="text-xs text-slate-500 mt-2">${
                data.new_findings.length < (data.totals?.new_findings ?? 0)
                    ? `Showing ${data.new_findings.length} of ${data.totals.new_findings} new findings — use <code>?limit=N</code> to load more`
                    : ''
            }</div>
        </div>
    `;

    window._compareData = data;
}

async function _pageComparePicker(el, scanA) {
    const scansData = await api('/scans');
    const archives = (scansData.archives || []).filter(a => a.scan_id !== scanA);

    el.innerHTML = `
        <div class="flex items-center gap-3 mb-6">
            <a href="#/archive/${esc(scanA)}" class="btn-secondary text-xs py-1 px-3 flex items-center gap-1.5">
                ${ICONS.arrowLeft} Back
            </a>
            <div>
                <h1 class="text-2xl font-bold text-white">Compare Scans</h1>
                <p class="text-sm text-slate-500 mt-1">
                    Select a scan to compare with <span class="font-mono text-slate-300">${esc(scanA)}</span> as the baseline
                </p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <!-- Fixed baseline -->
            <div class="card p-5 border-accent/40">
                <div class="text-[10px] text-slate-500 uppercase tracking-widest mb-3">Baseline (A) — Fixed</div>
                <div class="font-mono text-sm font-semibold text-accent">${esc(scanA)}</div>
            </div>

            <!-- Scan B picker -->
            <div class="space-y-3">
                <div class="text-xs text-slate-500 uppercase tracking-wider mb-1">Select Current (B)</div>

                <div class="archive-card cursor-pointer hover:border-accent/40 transition-colors"
                     onclick="navigateTo('compare', {id: '${esc(scanA)}', id2: 'current'})">
                    <div class="flex items-center gap-3">
                        <div class="timeline-dot active"></div>
                        <div>
                            <div class="text-sm font-medium text-white">Current Active Scan</div>
                            <div class="text-xs text-slate-500 mt-0.5">Live data from easm.duckdb</div>
                        </div>
                    </div>
                </div>

                ${archives.map(a => `
                    <div class="archive-card cursor-pointer hover:border-accent/40 transition-colors"
                         onclick="navigateTo('compare', {id: '${esc(scanA)}', id2: '${esc(a.scan_id)}'})">
                        <div class="flex items-center gap-3">
                            <div class="timeline-dot"></div>
                            <div>
                                <div class="font-mono text-sm text-white">${esc(a.scan_id)}</div>
                                <div class="text-xs text-slate-500 mt-0.5">
                                    ${fmtDate(a.archived_at)} · ${fmt((a.results || {}).total_assets || 0)} assets
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('')}

                ${archives.length === 0 ? `
                    <p class="text-sm text-slate-600 text-center py-6">No other archives available</p>
                ` : ''}
            </div>
        </div>
    `;
}

function _compareTabBtn(group, tab, label, count, active) {
    return `
        <button class="${group}-tab px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
            active ? 'bg-accent/20 text-accent border-accent/30' : 'bg-transparent text-slate-400 border-surface-border hover:border-slate-500'
        }" data-tab="${tab}" onclick="_compareTab('${group}', '${tab}')">
            ${label} <span class="ml-1 opacity-60">${count}</span>
        </button>
    `;
}

function _kpiRow(label, kpi, higherIsBad) {
    if (!kpi) return '';
    const d = kpi.delta;
    let cls = 'text-slate-500';
    if (d !== 0) cls = (higherIsBad ? d > 0 : d < 0) ? 'text-red-400' : 'text-green-400';
    const str = d > 0 ? `+${fmt(d)}` : fmt(d);
    const arrow = d > 0 ? ' ↑' : d < 0 ? ' ↓' : '';
    return `
        <tr>
            <td class="font-medium text-slate-300">${esc(label)}</td>
            <td class="text-slate-400">${fmt(kpi.a)}</td>
            <td class="text-slate-400">${fmt(kpi.b)}</td>
            <td class="${cls} font-semibold">${str}${arrow}</td>
        </tr>
    `;
}

function _newAssetsTable(assets) {
    if (!assets.length) return renderEmptyState('No new assets', '');
    return `
        <div class="overflow-x-auto">
            <table class="data-table">
                <thead><tr><th>FQDN</th><th>Ports</th><th>Web</th><th>Findings</th><th>CDN</th><th>ASN</th></tr></thead>
                <tbody>
                    ${assets.map(a => `
                        <tr>
                            <td class="font-mono text-xs text-green-400">${esc(a.fqdn)}</td>
                            <td>${a.port_count || 0}</td>
                            <td>${a.web_count || 0}</td>
                            <td>${a.finding_count ? `<span class="text-orange-400 font-medium">${a.finding_count}</span>` : '0'}</td>
                            <td class="text-slate-400 text-xs">${esc(a.cdn || '-')}</td>
                            <td class="text-slate-400 text-xs truncate max-w-[140px]">${esc(a.asn_org || '-')}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function _removedAssetsTable(assets) {
    if (!assets.length) return renderEmptyState('No removed assets', '');
    return `
        <div class="overflow-x-auto">
            <table class="data-table">
                <thead><tr><th>FQDN</th></tr></thead>
                <tbody>
                    ${assets.map(a => `
                        <tr><td class="font-mono text-xs text-red-400/70 line-through">${esc(a.fqdn)}</td></tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function _changedAssetsTable(assets) {
    if (!assets.length) return renderEmptyState('No changed assets', '');
    return `
        <div class="overflow-x-auto">
            <table class="data-table">
                <thead><tr>
                    <th>FQDN</th><th>New Ports</th><th>Closed Ports</th><th>New Findings</th><th>Resolved</th>
                </tr></thead>
                <tbody>
                    ${assets.map(a => `
                        <tr>
                            <td class="font-mono text-xs text-accent">${esc(a.fqdn)}</td>
                            <td class="text-xs text-green-400 font-mono">
                                ${a.new_ports.length ? a.new_ports.map(p => ':' + p).join(' ') : '-'}
                            </td>
                            <td class="text-xs text-red-400 font-mono">
                                ${a.closed_ports.length ? a.closed_ports.map(p => ':' + p).join(' ') : '-'}
                            </td>
                            <td class="text-xs">
                                ${a.new_findings.length
                                    ? a.new_findings.map(f => `<span class="badge badge-${esc(f.severity)}">${esc(f.severity)}</span>`).join(' ')
                                    : '-'}
                            </td>
                            <td class="text-xs text-slate-500">${a.resolved_findings.length || '-'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function _findingsTable(findings) {
    if (!findings.length) return renderEmptyState('No findings', '');
    return `
        <div class="overflow-x-auto">
            <table class="data-table">
                <thead><tr>
                    <th>Severity</th><th>FQDN</th><th>Finding</th><th>Template</th><th>Matched At</th>
                </tr></thead>
                <tbody>
                    ${findings.map(f => `
                        <tr>
                            <td>${severityBadge(f.severity)}</td>
                            <td class="font-mono text-xs text-accent">${esc(f.fqdn)}</td>
                            <td>${esc(f.finding_name)}</td>
                            <td class="font-mono text-xs text-slate-500">${esc(f.template_id)}</td>
                            <td class="text-xs text-slate-400">${esc(f.matched_at)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

window._compareTab = function(group, tab) {
    document.querySelectorAll(`.${group}-tab`).forEach(t => {
        const active = t.dataset.tab === tab;
        t.className = `${group}-tab px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
            active ? 'bg-accent/20 text-accent border-accent/30' : 'bg-transparent text-slate-400 border-surface-border hover:border-slate-500'
        }`;
    });

    const data = window._compareData;
    if (!data) return;

    const totals = data.totals || {};

    if (group === 'cmp-asset') {
        const el = document.getElementById('cmp-assets-content');
        const notice = document.getElementById('cmp-assets-notice');
        if (!el) return;
        let list, total, label;
        if (tab === 'new')     { list = data.new_assets;     total = totals.new_assets;     label = 'new assets';     el.innerHTML = _newAssetsTable(list); }
        if (tab === 'removed') { list = data.removed_assets; total = totals.removed_assets; label = 'removed assets'; el.innerHTML = _removedAssetsTable(list); }
        if (tab === 'changed') { list = data.changed_assets; total = totals.changed_assets; label = 'changed assets'; el.innerHTML = _changedAssetsTable(list); }
        if (notice) {
            notice.innerHTML = (list && total && list.length < total)
                ? `Showing ${list.length} of ${total} ${label} — use <code>?limit=N</code> to load more`
                : '';
        }
    } else if (group === 'cmp-finding') {
        const el = document.getElementById('cmp-findings-content');
        const notice = document.getElementById('cmp-findings-notice');
        if (!el) return;
        const isNew = tab === 'new';
        const list  = isNew ? data.new_findings : data.resolved_findings;
        const total = isNew ? totals.new_findings : totals.resolved_findings;
        const label = isNew ? 'new findings' : 'resolved findings';
        el.innerHTML = _findingsTable(list);
        if (notice) {
            notice.innerHTML = (list && total && list.length < total)
                ? `Showing ${list.length} of ${total} ${label} — use <code>?limit=N</code> to load more`
                : '';
        }
    }
};

// ---------------------------------------------------------------------------
// Page: CMDB Livecheck
// ---------------------------------------------------------------------------

const SCOPE_ACTION_STYLES = {
    keep:                { bg: 'rgba(34,197,94,0.12)',  border: '#22c55e', text: '#4ade80', label: 'Keep' },
    remove:              { bg: 'rgba(239,68,68,0.15)',  border: '#ef4444', text: '#fca5a5', label: 'Remove' },
    review_remove:       { bg: 'rgba(249,115,22,0.12)', border: '#f97316', text: '#fdba74', label: 'Review → Remove' },
    exclude_cdn:         { bg: 'rgba(139,92,246,0.12)', border: '#8b5cf6', text: '#c4b5fd', label: 'CDN Exclude' },
    review_cname_bloat:  { bg: 'rgba(234,179,8,0.12)',  border: '#eab308', text: '#fde047', label: 'CNAME Bloat' },
    monitor:             { bg: 'rgba(100,116,139,0.12)',border: '#6E827A', text: '#93A69E', label: 'Monitor' },
};

function scopeActionBadge(action) {
    const s = SCOPE_ACTION_STYLES[action] || SCOPE_ACTION_STYLES.monitor;
    return `<span class="text-[10px] px-2 py-0.5 rounded font-medium" style="color:${s.text};background:${s.bg};border:1px solid ${s.border}">${esc(s.label)}</span>`;
}

async function pageLivecheck(el) {
    let data;
    try {
        data = await api('/livecheck');
    } catch (e) {
        el.innerHTML = `
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h1 class="text-2xl font-bold text-white">CMDB Livecheck</h1>
                    <p class="text-sm text-slate-500 mt-1">DNS liveness &amp; Tenable scope governance</p>
                </div>
            </div>
            <div class="card p-10 text-center">
                <div class="text-slate-600 mb-4 flex justify-center">${ICONS.livecheck}</div>
                <p class="text-slate-300 font-medium mb-2">No livecheck data available</p>
                <p class="text-sm text-slate-500 mb-4">Run the pipeline in livecheck mode to validate CMDB scope.</p>
                <code class="text-xs text-accent bg-slate-800 px-3 py-1 rounded">./run.sh --mode livecheck</code>
            </div>
        `;
        return;
    }

    const s = data.summary || {};
    const scopeActions = data.scope_actions || [];
    const removals = data.scope_removals || [];
    const cdnExcl = data.cdn_exclusions || [];
    const cnameBloat = data.cname_bloat || [];
    const leaves = data.leaf_domains || [];
    const thirdPartyNs = data.third_party_ns || [];

    el.innerHTML = `
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-white">CMDB Livecheck</h1>
                <p class="text-sm text-slate-500 mt-1">DNS liveness, CDN detection &amp; Tenable scope governance</p>
            </div>
        </div>

        <!-- KPI Cards -->
        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
            ${_lcKpi('Total FQDNs', s.total_fqdns, '', 'cyan')}
            ${_lcKpi('Resolving', s.resolving, s.total_fqdns ? fmtPct((s.resolving||0)/(s.total_fqdns)*100) : '', 'green')}
            ${_lcKpi('Not Resolving', s.not_resolving, '', 'red')}
            ${_lcKpi('CDN Excluded', s.cdn_excluded, 'proposed', 'purple')}
            ${_lcKpi('Removal Candidates', s.removal_candidates, '≥30d down', 'orange')}
            ${_lcKpi('CNAME Bloat', s.cname_bloated, '>3 hops', 'yellow')}
            ${_lcKpi('3rd-Party NS', s.third_party_ns, 'delegated', 'blue')}
        </div>

        <!-- Scope Action Distribution -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Scope Action Distribution</h3>
                <div class="chart-container" style="height: 260px;">
                    <canvas id="chart-scope-actions"></canvas>
                </div>
            </div>
            <div class="card p-5">
                <h3 class="text-sm font-semibold text-slate-300 mb-4">Resolution Status</h3>
                <div class="chart-container" style="height: 260px;">
                    <canvas id="chart-resolution"></canvas>
                </div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="flex items-center gap-1 mb-4 border-b border-surface-border pb-px">
            <button class="lc-tab active" data-lc-tab="removals" onclick="switchLcTab('removals')">
                Scope Removals <span class="ml-1 text-[10px] text-red-400">${removals.length}</span>
            </button>
            <button class="lc-tab" data-lc-tab="cdn" onclick="switchLcTab('cdn')">
                CDN Exclusions <span class="ml-1 text-[10px] text-purple-400">${cdnExcl.length}</span>
            </button>
            <button class="lc-tab" data-lc-tab="cname" onclick="switchLcTab('cname')">
                CNAME Bloat <span class="ml-1 text-[10px] text-yellow-400">${cnameBloat.length}</span>
            </button>
            <button class="lc-tab" data-lc-tab="leaves" onclick="switchLcTab('leaves')">
                Leaf Domains <span class="ml-1 text-[10px] text-slate-400">${leaves.length}</span>
            </button>
            <button class="lc-tab" data-lc-tab="ns" onclick="switchLcTab('ns')">
                3rd-Party NS <span class="ml-1 text-[10px] text-blue-400">${thirdPartyNs.length}</span>
            </button>
        </div>

        <div id="lc-tab-content">
            ${_lcRemovalsTable(removals)}
        </div>
    `;

    // --- Charts ---
    const actionLabels = scopeActions.map(a => (SCOPE_ACTION_STYLES[a.scope_action] || {}).label || a.scope_action);
    const actionCounts = scopeActions.map(a => a.count);
    const actionColors = scopeActions.map(a => (SCOPE_ACTION_STYLES[a.scope_action] || SCOPE_ACTION_STYLES.monitor).text);

    createChart('chart-scope-actions', {
        type: 'doughnut',
        data: {
            labels: actionLabels,
            datasets: [{ data: actionCounts, backgroundColor: actionColors, borderWidth: 0 }],
        },
        options: {
            ...CHART_DEFAULTS,
            cutout: '55%',
            plugins: {
                ...CHART_DEFAULTS.plugins,
                legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
            },
        },
    });

    createChart('chart-resolution', {
        type: 'doughnut',
        data: {
            labels: ['Resolving', 'Not Resolving'],
            datasets: [{
                data: [s.resolving || 0, s.not_resolving || 0],
                backgroundColor: ['#22c55e', '#ef4444'],
                borderWidth: 0,
            }],
        },
        options: {
            ...CHART_DEFAULTS,
            cutout: '55%',
            plugins: {
                ...CHART_DEFAULTS.plugins,
                legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
            },
        },
    });

    // Store tab data for switching
    window._lcData = { removals, cdnExcl, cnameBloat, leaves, thirdPartyNs };
}

function _lcKpi(label, value, sub, color) {
    const colors = {
        cyan: 'text-cyan-400', green: 'text-green-400', red: 'text-red-400',
        orange: 'text-orange-400', yellow: 'text-yellow-400', blue: 'text-blue-400',
        purple: 'text-purple-400',
    };
    const c = colors[color] || 'text-slate-300';
    return `
        <div class="card p-4">
            <div class="text-[10px] text-slate-500 uppercase tracking-wider mb-1">${esc(label)}</div>
            <div class="text-2xl font-bold ${c}">${fmt(value)}</div>
            ${sub ? `<div class="text-[10px] text-slate-600 mt-0.5">${esc(sub)}</div>` : ''}
        </div>
    `;
}

window.switchLcTab = function(tab) {
    document.querySelectorAll('.lc-tab').forEach(b => b.classList.toggle('active', b.dataset.lcTab === tab));
    const content = document.getElementById('lc-tab-content');
    if (!content || !window._lcData) return;
    const d = window._lcData;
    switch (tab) {
        case 'removals': content.innerHTML = _lcRemovalsTable(d.removals); break;
        case 'cdn':      content.innerHTML = _lcCdnTable(d.cdnExcl); break;
        case 'cname':    content.innerHTML = _lcCnameTable(d.cnameBloat); break;
        case 'leaves':   content.innerHTML = _lcLeavesTable(d.leaves); break;
        case 'ns':       content.innerHTML = _lcNsTable(d.thirdPartyNs); break;
    }
};

function _lcRemovalsTable(items) {
    if (!items.length) return _lcEmpty('No scope removal candidates', 'All CMDB assets are resolving or within the 30-day monitoring window.');
    return `
        <div class="card overflow-hidden">
            <div class="px-5 py-3 border-b border-surface-border flex items-center justify-between">
                <h3 class="text-sm font-semibold text-slate-300">Scope Removal Candidates (≥30 days unavailable)</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead><tr class="border-b border-surface-border text-slate-500 uppercase tracking-wider">
                        <th class="px-4 py-2 text-left">FQDN</th>
                        <th class="px-4 py-2 text-left">CI ID</th>
                        <th class="px-4 py-2 text-left">Owner</th>
                        <th class="px-4 py-2 text-right">Days Down</th>
                        <th class="px-4 py-2 text-right">Scans Down</th>
                        <th class="px-4 py-2 text-left">Deadline</th>
                        <th class="px-4 py-2 text-center">Action</th>
                    </tr></thead>
                    <tbody>
                        ${items.map(r => `
                            <tr class="border-b border-surface-border hover:bg-white/[0.02]">
                                <td class="px-4 py-2.5 font-mono text-slate-200">${esc(r.fqdn)}</td>
                                <td class="px-4 py-2.5 text-slate-400">${esc(r.ci_id || '-')}</td>
                                <td class="px-4 py-2.5 text-slate-400">${esc(r.owner || '-')}</td>
                                <td class="px-4 py-2.5 text-right text-red-400 font-bold">${fmt(r.days_unavailable)}</td>
                                <td class="px-4 py-2.5 text-right text-slate-300">${fmt(r.consecutive_scans_down)}</td>
                                <td class="px-4 py-2.5 text-slate-400">${esc(r.removal_deadline || '-')}</td>
                                <td class="px-4 py-2.5 text-center">${scopeActionBadge(r.scope_action)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function _lcCdnTable(items) {
    if (!items.length) return _lcEmpty('No CDN exclusion proposals', 'No CMDB assets are behind a CDN with high enough confidence for exclusion.');
    return `
        <div class="card overflow-hidden">
            <div class="px-5 py-3 border-b border-surface-border">
                <h3 class="text-sm font-semibold text-slate-300">CDN/WAF Exclusion Proposals</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead><tr class="border-b border-surface-border text-slate-500 uppercase tracking-wider">
                        <th class="px-4 py-2 text-left">FQDN</th>
                        <th class="px-4 py-2 text-left">CI ID</th>
                        <th class="px-4 py-2 text-left">CDN Provider</th>
                        <th class="px-4 py-2 text-right">Confidence</th>
                        <th class="px-4 py-2 text-left">Signals</th>
                        <th class="px-4 py-2 text-center">Action</th>
                    </tr></thead>
                    <tbody>
                        ${items.map(r => `
                            <tr class="border-b border-surface-border hover:bg-white/[0.02]">
                                <td class="px-4 py-2.5 font-mono text-slate-200">${esc(r.fqdn)}</td>
                                <td class="px-4 py-2.5 text-slate-400">${esc(r.ci_id || '-')}</td>
                                <td class="px-4 py-2.5">
                                    <span class="text-purple-400 font-medium">${esc(r.cdn_provider || '-')}</span>
                                </td>
                                <td class="px-4 py-2.5 text-right ${confidenceClass(r.cdn_confidence)}">${r.cdn_confidence != null ? (r.cdn_confidence * 100).toFixed(0) + '%' : '-'}</td>
                                <td class="px-4 py-2.5 text-slate-500 max-w-[300px] truncate" title="${esc((r.cdn_signals||[]).join(', '))}">${esc((r.cdn_signals||[]).join(', '))}</td>
                                <td class="px-4 py-2.5 text-center">${scopeActionBadge(r.scope_action)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function _lcCnameTable(items) {
    if (!items.length) return _lcEmpty('No CNAME chain bloat detected', 'All FQDN CNAME chains are within the configured depth threshold.');
    return `
        <div class="card overflow-hidden">
            <div class="px-5 py-3 border-b border-surface-border">
                <h3 class="text-sm font-semibold text-slate-300">CNAME Chain Bloat</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead><tr class="border-b border-surface-border text-slate-500 uppercase tracking-wider">
                        <th class="px-4 py-2 text-left">FQDN</th>
                        <th class="px-4 py-2 text-right">Chain Depth</th>
                        <th class="px-4 py-2 text-left">CNAME Chain</th>
                        <th class="px-4 py-2 text-left">Fan-In Target</th>
                        <th class="px-4 py-2 text-right">Fan-In Count</th>
                        <th class="px-4 py-2 text-center">Resolves</th>
                        <th class="px-4 py-2 text-left">CDN</th>
                    </tr></thead>
                    <tbody>
                        ${items.map(r => `
                            <tr class="border-b border-surface-border hover:bg-white/[0.02]">
                                <td class="px-4 py-2.5 font-mono text-slate-200">${esc(r.fqdn)}</td>
                                <td class="px-4 py-2.5 text-right text-yellow-400 font-bold">${fmt(r.cname_chain_depth)}</td>
                                <td class="px-4 py-2.5 text-slate-500 max-w-[300px] truncate font-mono text-[10px]" title="${esc((r.cname_chain||[]).join(' → '))}">${esc((r.cname_chain||[]).join(' → '))}</td>
                                <td class="px-4 py-2.5 font-mono text-slate-400 text-[10px]">${esc(r.cname_fan_in_target || '-')}</td>
                                <td class="px-4 py-2.5 text-right text-slate-300">${r.cname_fan_in_count || '-'}</td>
                                <td class="px-4 py-2.5 text-center">${r.resolves ? '<span class="text-green-400">✓</span>' : '<span class="text-red-400">✗</span>'}</td>
                                <td class="px-4 py-2.5 text-purple-400">${esc(r.cdn_provider || '-')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function _lcLeavesTable(items) {
    if (!items.length) return _lcEmpty('No leaf domains found', 'All FQDNs have child subdomains.');
    return `
        <div class="card overflow-hidden">
            <div class="px-5 py-3 border-b border-surface-border">
                <h3 class="text-sm font-semibold text-slate-300">Leaf Domains (no child subdomains)</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead><tr class="border-b border-surface-border text-slate-500 uppercase tracking-wider">
                        <th class="px-4 py-2 text-left">FQDN</th>
                        <th class="px-4 py-2 text-center">In CMDB</th>
                        <th class="px-4 py-2 text-center">Resolves</th>
                        <th class="px-4 py-2 text-left">DNS Status</th>
                        <th class="px-4 py-2 text-left">CDN</th>
                        <th class="px-4 py-2 text-right">Days Down</th>
                        <th class="px-4 py-2 text-center">Action</th>
                    </tr></thead>
                    <tbody>
                        ${items.map(r => `
                            <tr class="border-b border-surface-border hover:bg-white/[0.02]">
                                <td class="px-4 py-2.5 font-mono text-slate-200">${esc(r.fqdn)}</td>
                                <td class="px-4 py-2.5 text-center">${r.in_cmdb ? '<span class="text-green-400">✓</span>' : '<span class="text-slate-600">-</span>'}</td>
                                <td class="px-4 py-2.5 text-center">${r.resolves ? '<span class="text-green-400">✓</span>' : '<span class="text-red-400">✗</span>'}</td>
                                <td class="px-4 py-2.5 text-slate-400">${esc(r.dns_status || '-')}</td>
                                <td class="px-4 py-2.5 text-purple-400">${esc(r.cdn_provider || '-')}</td>
                                <td class="px-4 py-2.5 text-right ${(r.days_unavailable||0) > 0 ? 'text-orange-400' : 'text-slate-500'}">${r.days_unavailable || '-'}</td>
                                <td class="px-4 py-2.5 text-center">${scopeActionBadge(r.scope_action)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function _lcNsTable(items) {
    if (!items.length) return _lcEmpty('No 3rd-party nameservers detected', 'All FQDNs use first-party nameservers.');
    return `
        <div class="card overflow-hidden">
            <div class="px-5 py-3 border-b border-surface-border">
                <h3 class="text-sm font-semibold text-slate-300">3rd-Party Nameserver Delegation</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead><tr class="border-b border-surface-border text-slate-500 uppercase tracking-wider">
                        <th class="px-4 py-2 text-left">FQDN</th>
                        <th class="px-4 py-2 text-left">NS Provider</th>
                        <th class="px-4 py-2 text-center">In CMDB</th>
                        <th class="px-4 py-2 text-center">Resolves</th>
                        <th class="px-4 py-2 text-left">CDN</th>
                    </tr></thead>
                    <tbody>
                        ${items.map(r => `
                            <tr class="border-b border-surface-border hover:bg-white/[0.02]">
                                <td class="px-4 py-2.5 font-mono text-slate-200">${esc(r.fqdn)}</td>
                                <td class="px-4 py-2.5">
                                    <span class="text-blue-400 font-medium">${esc(r.ns_provider || 'unknown')}</span>
                                </td>
                                <td class="px-4 py-2.5 text-center">${r.in_cmdb ? '<span class="text-green-400">✓</span>' : '<span class="text-slate-600">-</span>'}</td>
                                <td class="px-4 py-2.5 text-center">${r.resolves ? '<span class="text-green-400">✓</span>' : '<span class="text-red-400">✗</span>'}</td>
                                <td class="px-4 py-2.5 text-purple-400">${esc(r.cdn_provider || '-')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function _lcEmpty(title, desc) {
    return `
        <div class="card p-8 text-center">
            <p class="text-slate-400 font-medium">${esc(title)}</p>
            <p class="text-xs text-slate-600 mt-1">${esc(desc)}</p>
        </div>
    `;
}

// ---------------------------------------------------------------------------
// Page: Tenable Scope (VM / WAS routing)
// ---------------------------------------------------------------------------

const TS_CATEGORIES = {
    direct:         { label: 'Direct IP',           color: '#2FD9B0' },
    owned_shared:   { label: 'Owned shared IP',     color: '#5FE8C6' },
    non_http:       { label: 'Non-HTTP only',       color: '#A3E635' },
    api:            { label: 'API / AI endpoint',   color: '#4D9DFF' },
    cdn:            { label: 'Behind CDN',          color: '#a78bfa' },
    waf:            { label: 'Behind WAF',          color: '#f97316' },
    third_party:    { label: '3rd-party / hosting', color: '#F472B6' },
    cloud_paas:     { label: 'Cloud PaaS',          color: '#FBBF24' },
    static_or_dead: { label: 'Static / dead',       color: '#667A72' },
    takeover:       { label: 'Takeover',            color: '#ef4444' },
};

const TS_REASONS = {
    cdn: 'CDN edge', waf: 'WAF', third_party: '3rd-party', cloud_paas: 'Cloud PaaS',
    takeover: 'Takeover', non_routable: 'Non-routable IP', ownership_unverified: 'Ownership unverified',
    dead: 'Dead', no_open_ports: 'No open ports', redirect_only: 'Redirect only', parked: 'Parked',
    not_in_cmdb: 'Not in CMDB', non_http_only: 'No HTTP service', default_page: 'Default server page',
    no_app_content: 'No app content', cloud_storage: 'Cloud storage', static_hosting: 'Static hosting',
    managed_service: 'Managed service', third_party_saas: '3rd-party SaaS',
};

const TS_VM_COLORS = { include: '#2FD9B0', review: '#eab308', exclude: '#47564F' };
const TS_WAS_COLORS = { standard: '#2FD9B0', waf: '#f97316', api: '#4D9DFF', exclude: '#47564F' };

const TS_TABS = [
    { id: 'vm_include',   label: 'VM targets' },
    { id: 'vm_exclude',   label: 'VM exclusions' },
    { id: 'vm_review',    label: 'VM review' },
    { id: 'was_standard', label: 'WAS standard' },
    { id: 'was_waf',      label: 'WAS · WAF' },
    { id: 'was_api',      label: 'WAS · API' },
    { id: 'assets',       label: 'All assets' },
];

let tsState = { tab: 'vm_include', page: 1, q: '', category: '', vm: '', was: '', cmdb: '' };

function tsCategoryBadge(cat) {
    const c = TS_CATEGORIES[cat] || { label: cat || '-', color: '#667A72' };
    return `<span class="ts-chip" style="--chip:${c.color}"><span class="ts-dot"></span>${esc(c.label)}</span>`;
}

function tsActionBadge(action, colors) {
    const color = colors[action] || '#667A72';
    return `<span class="ts-chip" style="--chip:${color}"><span class="ts-dot"></span>${esc(action || '-')}</span>`;
}

function tsReasonLabel(reason) {
    const [kind, ...rest] = String(reason).split(':');
    const label = TS_REASONS[kind] || kind;
    const detail = rest.filter(Boolean).pop();
    return detail ? `${label} · ${detail}` : label;
}

function tsReasons(list) {
    if (!list || !list.length) return '<span class="text-slate-600">-</span>';
    return list.map(r => `<span class="ts-reason">${esc(tsReasonLabel(r))}</span>`).join(' ');
}

function tsSpectrum(parts, total) {
    const nonzero = parts.filter(p => p.value > 0);
    return `
        <div class="spectrum">
            ${total ? nonzero.map(p => `<span style="flex-grow:${p.value};background:${p.color}" title="${esc(p.label)}: ${fmt(p.value)}"></span>`).join('') : ''}
        </div>
        <div class="spectrum-legend">
            ${parts.map(p => `
                <span class="item"><span class="dot" style="background:${p.color}"></span>${esc(p.label)} <span class="val">${fmt(p.value)}</span></span>
            `).join('')}
        </div>
    `;
}

function tsModePair(key, value, cls = '', title = '') {
    return `<span class="inline-flex items-baseline gap-2 whitespace-nowrap" ${title ? `title="${esc(title)}"` : ''}>
        <span class="ts-mode-key">${esc(key)}</span><span class="ts-mode-val ${cls}">${esc(value)}</span></span>`;
}

function tsModeStrip(meta) {
    if (!meta) {
        return `<div class="ts-mode ts-mode-warn mb-4">Routing settings were not recorded for this run — re-run <code>./run.sh --stage scope</code>.</div>`;
    }
    const owned = [...(meta.owned_cidrs || []), ...(meta.owned_asns || []).map(a => `AS${a}`)];
    const enforced = !!meta.require_owned;
    return `
        <div class="ts-mode ${enforced ? '' : 'ts-mode-warn'} mb-4">
            <div class="flex flex-wrap items-center gap-x-6 gap-y-2">
                ${tsModePair('Ownership', enforced ? 'enforced — unowned IPs go to review' : 'not enforced',
                             enforced ? 'text-accent' : 'text-yellow-400')}
                ${tsModePair('Owned ranges', owned.length
                    ? owned.slice(0, 4).join(', ') + (owned.length > 4 ? ` +${owned.length - 4}` : '')
                    : 'none declared', '', owned.join(', '))}
                ${tsModePair('Scope', meta.cmdb_only ? 'CMDB-registered only' : 'all discovered assets')}
                ${tsModePair('Thresholds', `CDN ≥ ${meta.cdn_min_confidence} · WAF ≥ ${meta.waf_min_confidence}`)}
                ${tsModePair('SaaS → WAS', meta.was_include_saas ? 'yes' : 'no')}
                <span class="ml-auto">${tsModePair('Routed', fmtDate(meta.routed_at))}</span>
            </div>
            ${enforced ? '' : `
                <p class="text-xs text-slate-400 mt-2">
                    IPs are routed on observed signals only (CDN, WAF, 3rd-party, PaaS, takeover). Confirm ownership of
                    <span class="font-mono">VM targets</span> before importing them. Gate unknown IPs with
                    <span class="font-mono">TENABLE_OWNED_CIDRS</span> / <span class="font-mono">TENABLE_OWNED_ASNS</span>
                    and <span class="font-mono">TENABLE_VM_REQUIRE_OWNED=true</span>.
                </p>`}
        </div>
    `;
}

function tsReasonBars(title, rows, unit) {
    const byKind = {};
    rows.forEach(r => {
        const k = byKind[r.kind] || (byKind[r.kind] = { count: 0, detail: [] });
        k.count += r.count;
        k.detail.push(`${r.reason} (${r.count})`);
    });
    const kinds = Object.entries(byKind).sort((a, b) => b[1].count - a[1].count);
    const max = kinds.length ? kinds[0][1].count : 1;
    return `
        <div>
            <div class="eyebrow mb-3">${esc(title)}</div>
            ${kinds.length ? kinds.map(([kind, k]) => `
                <div class="ts-bar-row" title="${esc(k.detail.slice(0, 12).join('\n'))}">
                    <span class="ts-bar-label">${esc(TS_REASONS[kind] || kind)}</span>
                    <span class="ts-bar-track"><span style="width:${(k.count / max * 100).toFixed(1)}%"></span></span>
                    <span class="ts-bar-val">${fmt(k.count)}</span>
                </div>
            `).join('') : `<p class="text-xs text-slate-600">No ${esc(unit)} excluded</p>`}
        </div>
    `;
}

async function pageTenable(el) {
    let data;
    try {
        data = await api('/tenable-scope');
    } catch (e) {
        el.innerHTML = `
            <div class="mb-6">
                <h1 class="text-2xl font-bold text-white">Tenable Scope</h1>
                <p class="text-sm text-slate-500 mt-1">Scanner routing — Tenable VM by IP, Tenable WAS by URL</p>
            </div>
            <div class="card p-10 text-center">
                <div class="text-slate-600 mb-4 flex justify-center">${ICONS.tenable}</div>
                <p class="text-slate-300 font-medium mb-2">No scope routing for the current scan</p>
                <p class="text-sm text-slate-500 mb-4">Routing runs at the end of a recon scan. Re-route the loaded database without re-scanning:</p>
                <code class="text-xs text-accent bg-slate-800 px-3 py-1 rounded">./run.sh --stage scope</code>
            </div>
        `;
        return;
    }

    const vm = data.vm || {};
    const vmCount = a => (vm[a] || {}).ips || 0;
    const vmTotal = vmCount('include') + vmCount('review') + vmCount('exclude');
    const was = data.was_urls || {};
    const wasUrls = (was.standard || 0) + (was.waf || 0) + (was.api || 0);
    const assets = data.assets || {};
    const included = vm.include || {};

    el.innerHTML = `
        <div class="flex items-start justify-between gap-4 mb-5">
            <div>
                <h1 class="text-2xl font-bold text-white">Tenable Scope</h1>
                <p class="text-sm text-slate-500 mt-1">
                    ${fmt(assets.total)} assets routed${data.meta && data.meta.scan_id ? ` · scan <span class="font-mono">${esc(data.meta.scan_id)}</span>` : ''}
                    · ${fmt(assets.in_cmdb)} in CMDB
                </p>
            </div>
        </div>

        ${tsModeStrip(data.meta)}

        <div class="readout mb-6">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div>
                    <div class="eyebrow mb-2">Tenable VM · network, by IP</div>
                    <div class="flex items-baseline gap-3 mb-3">
                        <span class="kpi-value text-4xl">${fmt(vmCount('include'))}</span>
                        <span class="text-sm text-slate-500">IPs to scan${included.fqdns ? ` · covering ${fmt(included.fqdns)} FQDNs` : ''}${included.shared_ips ? ` · ${fmt(included.shared_ips)} shared` : ''}</span>
                    </div>
                    ${tsSpectrum([
                        { label: 'include', value: vmCount('include'), color: TS_VM_COLORS.include },
                        { label: 'review', value: vmCount('review'), color: TS_VM_COLORS.review },
                        { label: 'exclude', value: vmCount('exclude'), color: TS_VM_COLORS.exclude },
                    ], vmTotal)}
                </div>
                <div>
                    <div class="eyebrow mb-2">Tenable WAS · DAST, by URL</div>
                    <div class="flex items-baseline gap-3 mb-3">
                        <span class="kpi-value text-4xl">${fmt(wasUrls)}</span>
                        <span class="text-sm text-slate-500">URLs from ${fmt(assets.was_included)} assets · ${fmt(assets.was_excluded)} assets not DAST targets</span>
                    </div>
                    ${tsSpectrum([
                        { label: 'standard', value: was.standard || 0, color: TS_WAS_COLORS.standard },
                        { label: 'waf allow-list', value: was.waf || 0, color: TS_WAS_COLORS.waf },
                        { label: 'api', value: was.api || 0, color: TS_WAS_COLORS.api },
                    ], wasUrls)}
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_22rem] gap-4 mb-6">
            <div class="card overflow-hidden">
                <div class="px-5 py-3 border-b border-surface-border flex items-center justify-between">
                    <h3 class="text-sm font-semibold text-slate-300">Routing matrix</h3>
                    <span class="text-[10px] text-slate-600 font-mono">assets · click a row to list them</span>
                </div>
                <div class="overflow-x-auto">
                    <table class="data-table w-full text-xs">
                        <thead><tr>
                            <th class="text-left">Category</th>
                            <th class="text-right">Assets</th>
                            <th class="text-right">VM incl</th>
                            <th class="text-right">VM excl</th>
                            <th class="text-right">WAS std</th>
                            <th class="text-right">WAS waf</th>
                            <th class="text-right">WAS api</th>
                            <th class="text-right">WAS excl</th>
                        </tr></thead>
                        <tbody>
                            ${(data.categories || []).map(c => `
                                <tr class="clickable" onclick="tsFilterCategory('${esc(c.category)}')">
                                    <td>${tsCategoryBadge(c.category)}</td>
                                    <td class="text-right text-slate-200 font-semibold">${fmt(c.assets)}</td>
                                    ${['vm_include', 'vm_exclude', 'was_standard', 'was_waf', 'was_api', 'was_exclude'].map(k =>
                                        `<td class="text-right font-mono ${c[k] ? 'text-slate-300' : 'text-slate-700'}">${fmt(c[k])}</td>`).join('')}
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="card p-5 flex flex-col gap-6">
                ${tsReasonBars('Why IPs stay out of VM', data.vm_reasons || [], 'IPs')}
                ${tsReasonBars('Why assets are not DAST targets', data.was_reasons || [], 'assets')}
            </div>
        </div>

        <div class="card p-4 mb-6">
            <div class="flex flex-wrap items-center gap-2">
                <span class="eyebrow mr-2">Import files</span>
                ${[
                    ['vm_include', 'VM include', vmCount('include')],
                    ['vm_exclude', 'VM exclude', vmCount('exclude')],
                    ['vm_review', 'VM review', vmCount('review')],
                    ['was_standard', 'WAS standard', was.standard || 0],
                    ['was_waf', 'WAS WAF', was.waf || 0],
                    ['was_api', 'WAS API', was.api || 0],
                ].map(([kind, label, n]) => `
                    <button class="btn-secondary text-xs py-1 px-2" onclick="tsDownload('${kind}')" ${n ? '' : 'disabled'}>
                        ${ICONS.download}<span>${label}</span><span class="font-mono text-slate-500">${fmt(n)}</span>
                    </button>
                `).join('')}
                <span class="mx-1 h-5 border-l border-surface-border"></span>
                <button class="btn-secondary text-xs py-1 px-2" onclick="tsDownload('assets')">${ICONS.download}<span>Per-asset CSV</span></button>
                <button class="btn-secondary text-xs py-1 px-2" onclick="tsDownload('vm_targets')">${ICONS.download}<span>Per-IP CSV</span></button>
                <span class="mx-1 h-5 border-l border-surface-border"></span>
                <button class="btn-secondary text-xs py-1 px-2" onclick="tsDownload('xlsx')"
                        title="Workbook: Summary, All, Tenable VM Candidates, Tenable WAS Candidates, Columns">
                    ${ICONS.download}<span>XLSX workbook</span>
                </button>
            </div>
        </div>

        <div class="flex flex-wrap items-center gap-1 mb-4 border-b border-surface-border pb-px">
            ${TS_TABS.map(t => {
                const n = t.id.startsWith('vm_') ? vmCount(t.id.slice(3))
                        : t.id === 'assets' ? assets.total : was[t.id.slice(4)] || 0;
                return `<button class="lc-tab ${tsState.tab === t.id ? 'active' : ''}" data-ts-tab="${t.id}" onclick="tsSwitchTab('${t.id}')">
                    ${t.label} <span class="ml-1 text-[10px] text-slate-500 font-mono">${fmt(n)}</span></button>`;
            }).join('')}
        </div>
        <div id="ts-filters" class="flex flex-wrap items-center gap-3 mb-4"></div>
        <div id="ts-tab-content">${renderLoadingState()}</div>
    `;

    window._tsCategories = (data.categories || []).map(c => c.category);
    tsRenderFilters();
    await tsLoad();
}

function tsRenderFilters() {
    const box = document.getElementById('ts-filters');
    if (!box) return;
    const isAssets = tsState.tab === 'assets';
    const isWas = tsState.tab.startsWith('was_');
    const opt = (v, label, cur) => `<option value="${v}" ${cur === v ? 'selected' : ''}>${esc(label)}</option>`;
    box.innerHTML = `
        <div class="relative flex-1 min-w-[240px] max-w-md">
            <div class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">${ICONS.search}</div>
            <input type="text" id="ts-search" class="search-input" value="${esc(tsState.q)}"
                   placeholder="${tsState.tab.startsWith('vm_') ? 'Search IP, FQDN or ASN…' : 'Search FQDN, URL or IP…'}">
        </div>
        ${isAssets || isWas ? `
            <select class="search-input max-w-[200px]" onchange="tsSetFilter('category', this.value)">
                ${opt('', 'All categories', tsState.category)}
                ${(window._tsCategories || []).map(c => opt(c, (TS_CATEGORIES[c] || {}).label || c, tsState.category)).join('')}
            </select>` : ''}
        ${isAssets ? `
            <select class="search-input max-w-[150px]" onchange="tsSetFilter('vm', this.value)">
                ${opt('', 'VM: any', tsState.vm)}${opt('include', 'VM: include', tsState.vm)}${opt('exclude', 'VM: exclude', tsState.vm)}${opt('review', 'VM: review', tsState.vm)}
            </select>
            <select class="search-input max-w-[160px]" onchange="tsSetFilter('was', this.value)">
                ${opt('', 'WAS: any', tsState.was)}${opt('standard', 'WAS: standard', tsState.was)}${opt('waf', 'WAS: waf', tsState.was)}${opt('api', 'WAS: api', tsState.was)}${opt('exclude', 'WAS: exclude', tsState.was)}
            </select>
            <select class="search-input max-w-[150px]" onchange="tsSetFilter('cmdb', this.value)">
                ${opt('', 'CMDB: any', tsState.cmdb)}${opt('1', 'In CMDB', tsState.cmdb)}${opt('0', 'Not in CMDB', tsState.cmdb)}
            </select>` : ''}
    `;
    document.getElementById('ts-search').addEventListener('input', debounce(e => {
        tsState.q = e.target.value;
        tsState.page = 1;
        tsLoad();
    }, 300));
}

async function tsLoad() {
    const content = document.getElementById('ts-tab-content');
    if (!content) return;
    const s = tsState;
    let data;
    try {
        data = await api('/tenable-scope/list', {
            kind: s.tab, q: s.q, page: s.page, per_page: 50,
            category: s.category, vm: s.vm, was: s.was, cmdb: s.cmdb,
        });
    } catch (e) {
        content.innerHTML = renderErrorState(e.message);
        return;
    }
    if (!data.items.length) {
        content.innerHTML = _lcEmpty('Nothing here', s.q || s.category || s.vm || s.was || s.cmdb
            ? 'No rows match the current filters.' : 'This list is empty for the current scan.');
        return;
    }
    const table = s.tab.startsWith('vm_') ? tsVmTable(data.items, s.tab)
                : s.tab === 'assets' ? tsAssetsTable(data.items) : tsWasTable(data.items, s.tab);
    content.innerHTML = `
        <div class="card overflow-hidden">
            <div class="overflow-x-auto">${table}</div>
            <div class="flex items-center justify-between">
                <span class="text-[10px] text-slate-600 font-mono px-4">${fmt(data.total)} rows</span>
                ${data.pages > 1 ? renderPagination(data.page, data.pages, 'ts') : ''}
            </div>
        </div>
    `;
}

function tsFqdnLink(fqdn) {
    return `<button class="font-mono text-slate-200 hover:text-accent text-left" onclick="openAssetPanel('${esc(fqdn)}')">${esc(fqdn)}</button>`;
}

function tsVmTable(items, tab) {
    const excl = tab === 'vm_exclude';
    return `
        <table class="data-table w-full text-xs">
            <thead><tr>
                <th class="text-left">IP</th>
                <th class="text-left">Primary FQDN</th>
                <th class="text-right">FQDNs</th>
                <th class="text-left">${excl ? 'Reasons' : 'Type'}</th>
                <th class="text-left">Ports</th>
                <th class="text-left">ASN org</th>
                <th class="text-center">Owned</th>
            </tr></thead>
            <tbody>
                ${items.map(r => `
                    <tr>
                        <td class="font-mono text-slate-200">${esc(r.target_ip)}</td>
                        <td>${r.primary_fqdn && r.primary_fqdn !== r.target_ip ? tsFqdnLink(r.primary_fqdn) : '<span class="text-slate-600">-</span>'}</td>
                        <td class="text-right font-mono text-slate-300" title="${esc((r.fqdns || []).join('\n'))}">${fmt(r.fqdn_count)}</td>
                        <td>${excl ? tsReasons(r.reasons) : tsCategoryBadge(r.vm_category)}</td>
                        <td class="font-mono text-slate-400" title="${esc((r.ports || []).join(', '))}">${esc((r.ports || []).slice(0, 8).join(', '))}${(r.ports || []).length > 8 ? ` +${r.ports.length - 8}` : ''}</td>
                        <td class="text-slate-400 max-w-[220px] truncate" title="${esc(r.asn_org || '')}">${esc(r.asn_org || '-')}</td>
                        <td class="text-center">${r.owned ? '<span class="text-accent">✓</span>' : '<span class="text-slate-600">-</span>'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

function tsWasTable(items, tab) {
    return `
        <table class="data-table w-full text-xs">
            <thead><tr>
                <th class="text-left">Target URL</th>
                <th class="text-left">FQDN</th>
                <th class="text-left">Category</th>
                <th class="text-left">${tab === 'was_api' ? 'Platforms' : 'WAF / CDN'}</th>
                <th class="text-center">CMDB</th>
            </tr></thead>
            <tbody>
                ${items.map(r => `
                    <tr>
                        <td class="font-mono text-slate-200">${esc(r.target_url)}</td>
                        <td>${tsFqdnLink(r.fqdn)}</td>
                        <td>${tsCategoryBadge(r.category)}</td>
                        <td class="text-slate-400">${tab === 'was_api'
                            ? esc((r.platforms || []).join(', ') || '-')
                            : esc([r.waf_provider, r.cdn_provider].filter(Boolean).join(' / ') || '-')}</td>
                        <td class="text-center">${r.in_cmdb ? '<span class="text-accent">✓</span>' : '<span class="text-slate-600">-</span>'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

function tsAssetsTable(items) {
    return `
        <table class="data-table w-full text-xs">
            <thead><tr>
                <th class="text-left">FQDN</th>
                <th class="text-left">Category</th>
                <th class="text-left">VM</th>
                <th class="text-left">WAS</th>
                <th class="text-left">IPs</th>
                <th class="text-center">CMDB</th>
            </tr></thead>
            <tbody>
                ${items.map(r => `
                    <tr>
                        <td>${tsFqdnLink(r.fqdn)}</td>
                        <td title="${esc((r.categories || []).join(', '))}">${tsCategoryBadge(r.category)}</td>
                        <td>${tsActionBadge(r.vm_action, TS_VM_COLORS)} ${r.vm_action === 'include' ? '' : tsReasons(r.vm_reasons)}</td>
                        <td>${r.was_action === 'include' ? tsActionBadge(r.was_profile, TS_WAS_COLORS) : `${tsActionBadge('exclude', TS_WAS_COLORS)} ${tsReasons(r.was_reasons)}`}</td>
                        <td class="font-mono text-slate-400" title="${esc((r.ips || []).join('\n'))}">${esc((r.ips || []).slice(0, 2).join(', '))}${(r.ips || []).length > 2 ? ` +${r.ips.length - 2}` : ''}</td>
                        <td class="text-center">${r.in_cmdb ? '<span class="text-accent">✓</span>' : '<span class="text-slate-600">-</span>'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

window.tsSwitchTab = function(tab) {
    tsState = { ...tsState, tab, page: 1, q: '', vm: '', was: '', cmdb: '',
                category: tab === 'assets' || tab.startsWith('was_') ? tsState.category : '' };
    document.querySelectorAll('[data-ts-tab]').forEach(b => b.classList.toggle('active', b.dataset.tsTab === tab));
    tsRenderFilters();
    tsLoad();
};

window.tsSetFilter = function(key, value) {
    tsState[key] = value;
    tsState.page = 1;
    tsLoad();
};

window.tsFilterCategory = function(category) {
    tsState.category = category;
    tsSwitchTab('assets');
    document.getElementById('ts-filters')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

window.tsPage = function(p) {
    tsState.page = p;
    tsLoad();
};

window.tsDownload = async function(kind) {
    try {
        const res = await fetch(`/api/tenable-scope/export?kind=${encodeURIComponent(kind)}`);
        if (!res.ok) { alert('Export failed'); return; }
        const name = (res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/);
        const url = URL.createObjectURL(await res.blob());
        const a = document.createElement('a');
        a.href = url;
        a.download = name ? name[1] : `tenable_${kind}.${kind === 'xlsx' ? 'xlsx' : 'txt'}`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) { alert('Export error: ' + e.message); }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function capitalize(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
    await ensureAuth();
    initRouter();
});
