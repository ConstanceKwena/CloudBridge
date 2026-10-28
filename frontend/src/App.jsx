import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowRight, Bell, Check, CircleHelp,
  Cloud, Database, DollarSign, ExternalLink, LayoutDashboard, LogOut,
  Menu, Plus, RefreshCw, Search, Server, Shield, ShieldAlert, X,
} from "lucide-react";
import { apiRequest } from "./api";
import { AuthPage } from "./AuthPage";

const navigation = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "resources", label: "Resources", icon: Server },
  { id: "monitoring", label: "Monitoring", icon: Activity },
  { id: "security", label: "Security Center", icon: ShieldAlert },
  { id: "costs", label: "Cost Analytics", icon: DollarSign },
  { id: "connections", label: "Connections", icon: Cloud },
  { id: "alerts", label: "Alerts", icon: Bell },
];
const todayLabel = new Intl.DateTimeFormat("en-GB", {
  weekday: "long",
  day: "2-digit",
  month: "long",
  year: "numeric",
}).format(new Date()).toUpperCase();

const severityClass = (severity) => `severity severity-${severity}`;

function formatProvider(provider) {
  return { aws: "AWS", azure: "Azure", gcp: "Google Cloud" }[provider] || provider;
}

function formatResourceType(type) {
  return type.charAt(0).toUpperCase() + type.slice(1);
}

function formatSeverity(severity) {
  return severity === "info" ? "Informational" : severity.charAt(0).toUpperCase() + severity.slice(1);
}

function formatTimestamp(value) {
  if (!value) return "Not synchronized";
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function metricValue(value) {
  return value === null || value === undefined ? "Unavailable" : `${Number(value).toFixed(1)}%`;
}

function ResourceIcon({ type }) {
  if (type === "storage") return <Database size={16} />;
  if (type === "database") return <Database size={16} />;
  return <Server size={16} />;
}

function SummaryCard({ label, value, note, icon: Icon, tone }) {
  return (
    <article className="summary-card">
      <div className="summary-top">
        <span className={`summary-icon ${tone}`}><Icon size={18} /></span>
      </div>
      <div className="summary-label">{label}</div>
      <div className="summary-value">{value}</div>
      <div className="summary-note">{note}</div>
    </article>
  );
}

function ResourceTable({ resources, compact = false }) {
  if (!resources.length) {
    return <div className="empty-state"><Cloud size={22} /><strong>No resources found</strong><span>Try changing your filters or add a simulated resource.</span></div>;
  }
  return (
    <div className="table-scroll">
      <table className="resource-table">
        <thead><tr><th>RESOURCE</th><th>TYPE</th><th>REGION</th><th>STATUS</th><th>CPU</th><th>MEMORY</th><th>SOURCE</th></tr></thead>
        <tbody>
          {resources.slice(0, compact ? 5 : undefined).map((resource) => (
            <tr key={resource.id}>
              <td><span className="resource-name"><span className="resource-icon"><ResourceIcon type={resource.resource_type} /></span><span>{resource.name}<small>{formatProvider(resource.provider)}</small></span></span></td>
              <td>{formatResourceType(resource.resource_type)}</td>
              <td className="muted-cell">{resource.region}</td>
              <td><span className={`status-pill status-${resource.status.toLowerCase()}`}><i />{resource.status}</span></td>
              <td className="muted-cell">{metricValue(resource.metrics?.cpu_utilization)}</td>
              <td className="muted-cell">{metricValue(resource.metrics?.memory_utilization)}</td>
              <td><span className={resource.simulated ? "simulated-tag" : "live-tag"}><span />{resource.simulated ? "Demo" : "AWS"}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AlertList({ alerts, compact = false, onAcknowledge, onResolve }) {
  if (!alerts.length) {
    return <div className="empty-state"><Bell size={22} /><strong>You’re all caught up</strong><span>New alerts will appear here.</span></div>;
  }
  return (
    <div className="alert-list">
      {alerts.slice(0, compact ? 3 : undefined).map((alert) => (
        <article className="alert-row" key={alert.id}>
          <span className={`alert-symbol alert-${alert.severity}`}><AlertTriangle size={16} /></span>
          <div className="alert-content"><div className="alert-title">{alert.title}</div><p>{alert.message}</p><small>{formatSeverity(alert.severity)} priority · {formatTimestamp(alert.created_at)} · {alert.simulated ? "demo" : "live"}</small></div>
          {!alert.is_read && <span className="unread-dot" aria-label="Unread" />}
          {alert.status !== "resolved" && <span className="alert-actions">
            {alert.status === "active" && <button className="text-button" onClick={() => onAcknowledge(alert.id)}>Acknowledge</button>}
            <button className="text-button" onClick={() => onResolve(alert.id)}>Resolve</button>
          </span>}
        </article>
      ))}
    </div>
  );
}

function ConnectionDialog({ onClose, onCreated, token }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState("demo");
  const [provider, setProvider] = useState("aws");

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const provider = String(form.get("provider"));
      await apiRequest(provider === "aws" && mode === "live" ? "/connections/aws" : "/connections", {
        token,
        method: "POST",
        body: JSON.stringify({
          ...(provider === "aws" && mode === "live" ? {} : { provider }),
          display_name: String(form.get("display_name")).trim(),
          region: String(form.get("region")).trim() || (provider === "aws" && mode === "live" ? "us-east-1" : null),
          ...(provider === "aws" && mode === "live"
            ? {}
            : { account_identifier: String(form.get("account_identifier")).trim() || null }),
        }),
      });
      onCreated();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section role="dialog" aria-modal="true" aria-labelledby="connect-title" className="modal-card">
        <div className="modal-heading"><div><span className="section-kicker">NEW CONNECTION</span><h2 id="connect-title">Add a cloud account</h2></div><button className="icon-button" onClick={onClose} aria-label="Close"><X size={19} /></button></div>
        <p className="modal-description">Connect read-only AWS access or create an explicitly labeled demo record.</p>
        {error && <div role="alert" className="error-banner">{error}</div>}
        <form className="dialog-form" onSubmit={submit}>
          <label>Cloud provider<select name="provider" value={provider} onChange={(event) => { setProvider(event.target.value); setMode("demo"); }}><option value="aws">Amazon Web Services</option><option value="azure">Microsoft Azure (demo)</option><option value="gcp">Google Cloud Platform (demo)</option></select></label>
          <label>Connection mode<select value={mode} onChange={(event) => setMode(event.target.value)}><option value="demo">Demo Mode — simulated data</option><option value="live" disabled={provider !== "aws"}>Live AWS — use backend credentials</option></select></label>
          <label>Connection name<input name="display_name" minLength="2" maxLength="100" placeholder="e.g. Production account" required /></label>
          <div className="field-pair">
            <label>Default region<input name="region" maxLength="64" placeholder="us-east-1" /></label>
            {mode === "demo" && <label>Account reference <span className="optional-label">optional</span><input name="account_identifier" maxLength="128" placeholder="For your reference" /></label>}
          </div>
          <div className="demo-notice"><Shield size={16} /><span>{mode === "live" ? <><strong>No credentials are entered here.</strong> The backend uses its standard AWS credential provider chain and validates access through STS.</> : <><strong>Demo Mode.</strong> This saves a simulated record; no provider credentials are collected or connected.</>}</span></div>
          <div className="modal-actions"><button type="button" className="secondary-button" onClick={onClose}>Cancel</button><button type="submit" className="primary-button" disabled={busy}>{busy ? "Saving…" : "Save connection"}{!busy && <ArrowRight size={16} />}</button></div>
        </form>
      </section>
    </div>
  );
}

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("cloudbridge_token"));
  const [user, setUser] = useState(null);
  const [view, setView] = useState("overview");
  const [summary, setSummary] = useState(null);
  const [resources, setResources] = useState([]);
  const [connections, setConnections] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [findings, setFindings] = useState([]);
  const [costReport, setCostReport] = useState(null);
  const [costError, setCostError] = useState("");
  const [scanChecks, setScanChecks] = useState({});
  const [syncMessage, setSyncMessage] = useState("");
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [providerFilter, setProviderFilter] = useState("all");
  const [regionFilter, setRegionFilter] = useState("all");
  const [alertSeverity, setAlertSeverity] = useState("all");
  const [alertStatus, setAlertStatus] = useState("active");
  const [showConnectionDialog, setShowConnectionDialog] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const logout = useCallback(() => {
    localStorage.removeItem("cloudbridge_token");
    setToken(null);
    setUser(null);
    setSummary(null);
    setResources([]);
    setConnections([]);
    setAlerts([]);
    setFindings([]);
    setCostReport(null);
    setCostError("");
    setError("");
  }, []);

  const loadDashboard = useCallback(async (activeToken) => {
    setLoading(true);
    setError("");
    try {
      const [profile, dashboardSummary, resourceList, connectionList, alertList, findingList] = await Promise.all([
        apiRequest("/auth/me", { token: activeToken }),
        apiRequest("/dashboard/summary", { token: activeToken }),
        apiRequest("/resources", { token: activeToken }),
        apiRequest("/connections", { token: activeToken }),
        apiRequest("/alerts", { token: activeToken }),
        apiRequest("/security/findings", { token: activeToken }),
      ]);
      setUser(profile);
      setSummary(dashboardSummary);
      setResources(resourceList);
      setConnections(connectionList);
      setAlerts(alertList);
      setFindings(findingList);
      const awsConnection = connectionList.find((connection) => connection.provider === "aws");
      if (awsConnection) {
        try {
          setCostReport(await apiRequest(`/connections/${awsConnection.id}/costs`, { token: activeToken }));
          setCostError("");
        } catch (costLoadError) {
          setCostReport(null);
          setCostError(costLoadError.message);
        }
      } else {
        setCostReport(null);
        setCostError("");
      }
    } catch (loadError) {
      if (loadError.status === 401) {
        logout();
      } else {
        setError(loadError.message);
      }
    } finally {
      setLoading(false);
    }
  }, [logout]);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }
    localStorage.setItem("cloudbridge_token", token);
    loadDashboard(token);
  }, [token, loadDashboard]);

  const filteredResources = useMemo(() => resources.filter((resource) => {
    const matchesProvider = providerFilter === "all" || resource.provider === providerFilter;
    const matchesRegion = regionFilter === "all" || resource.region === regionFilter;
    const searchText = `${resource.name} ${resource.region} ${resource.resource_type}`.toLowerCase();
    return matchesProvider && matchesRegion && searchText.includes(query.toLowerCase());
  }), [resources, providerFilter, regionFilter, query]);
  const visibleAlerts = alerts.filter((alert) => {
    const matchesStatus = alertStatus === "all"
      || (alertStatus === "active" && alert.status !== "resolved")
      || alert.status === "resolved";
    return matchesStatus && (alertSeverity === "all" || alert.severity === alertSeverity);
  });
  const liveAWS = connections.find((connection) => connection.provider === "aws" && !connection.simulated);

  async function refreshInventory() {
    const connection = connections.find((item) => item.provider === "aws");
    if (!connection) return;
    setSyncMessage("");
    try {
      const result = await apiRequest(`/connections/${connection.id}/sync`, { token, method: "POST" });
      setSyncMessage(result.simulated
        ? "Demo Mode inventory is static sample data."
        : `${result.resource_count} resources synchronized at ${formatTimestamp(result.synchronized_at)}${result.warnings.length ? ` · ${result.warnings.join(" ")}` : ""}`);
      await loadDashboard(token);
    } catch (syncError) {
      setError(syncError.message);
    }
  }

  async function runSecurityScan() {
    const connection = connections.find((item) => item.provider === "aws");
    if (!connection) return;
    setScanning(true);
    setError("");
    try {
      const report = await apiRequest(`/connections/${connection.id}/scan`, { token, method: "POST" });
      setScanChecks(report.checks);
      await loadDashboard(token);
    } catch (scanError) {
      setError(scanError.message);
    } finally {
      setScanning(false);
    }
  }

  async function updateAlert(alertId, action) {
    try {
      await apiRequest(`/alerts/${alertId}/${action}`, { token, method: "PATCH" });
      await loadDashboard(token);
    } catch (alertError) {
      setError(alertError.message);
    }
  }

  function navigate(nextView) {
    setView(nextView);
    setMobileNavOpen(false);
  }

  if (!token) {
    return <AuthPage onAuthenticated={(newToken) => setToken(newToken)} />;
  }

  return (
    <div className="app-shell">
      {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
      <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}>
        <div className="sidebar-brand">
          <span className="brand-mark"><Cloud size={20} /></span>
          <span>cloud<span className="brand-accent">bridge</span></span>
          <button className="mobile-close icon-button" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)}><X size={18} /></button>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <div className="workspace-select"><span className="workspace-avatar">C</span><span className="workspace-name">Cloud workspace<small>Personal workspace</small></span></div>
        <div className="nav-label">PLATFORM</div>
        <nav className="primary-nav" aria-label="Main navigation">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button className={`nav-item ${view === id ? "nav-active" : ""}`} key={id} onClick={() => navigate(id)}>
              <Icon size={18} /><span>{label}</span>{id === "alerts" && summary?.unread_alerts > 0 && <span className="nav-count">{summary.unread_alerts}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-status"><span className="pulse-dot" /><span>{liveAWS ? "AWS connection active" : "Demo workspace ready"}<small>{liveAWS ? `Last sync ${formatTimestamp(liveAWS.last_synced_at)}` : "Simulated inventory loaded"}</small></span></div>
          <a className="help-link" href="/docs" target="_blank" rel="noreferrer"><CircleHelp size={17} /> API documentation<ExternalLink size={14} /></a>
          <div className="profile-block"><span className="profile-avatar">{user?.full_name?.[0]?.toUpperCase() || "U"}</span><span className="profile-name">{user?.full_name}<small>{user?.email}</small></span><button className="logout-button" onClick={logout} aria-label="Sign out"><LogOut size={17} /></button></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Menu size={20} /></button>
          <div className="breadcrumb">CloudBridge <span>/</span> <strong>{navigation.find((item) => item.id === view)?.label || "Overview"}</strong></div>
          <div className="topbar-right"><span className="environment-tag"><span /> {liveAWS ? "LIVE AWS + DEMO" : "DEMO ENVIRONMENT"}</span><button className="topbar-icon icon-button" aria-label="View alerts" onClick={() => navigate("alerts")}><Bell size={18} />{summary?.unread_alerts > 0 && <i />}</button><span className="topbar-avatar">{user?.full_name?.[0]?.toUpperCase() || "U"}</span></div>
        </header>

        <div className="page-content">
          {error && <div className="page-error" role="alert"><AlertTriangle size={18} /><span>{error}</span><button className="secondary-button" onClick={() => loadDashboard(token)}>Retry</button></div>}
          {loading && <div className="loading-panel"><span className="spinner" /><span>Loading your cloud workspace…</span></div>}
          {!loading && !error && (
            <>
              {view === "overview" && (
                <>
                  <section className="page-heading">
                    <div><div className="section-kicker">{todayLabel} <span className="heading-separator">/</span> LIVE WORKSPACE</div><h1>Good to have you here, {user?.full_name?.split(" ")[0]}.</h1><p>Here’s what’s happening across your cloud environment.</p></div>
                    <button className="primary-button" onClick={() => setShowConnectionDialog(true)}><Plus size={17} /> Add connection</button>
                  </section>
                  <div className="demo-banner"><span className="demo-banner-icon"><Activity size={16} /></span><div><strong>{liveAWS ? "Live AWS monitoring is enabled." : "You’re viewing a simulated workspace."}</strong><span>{liveAWS ? "Live inventory is synchronized from AWS; demo resources remain clearly labeled." : "Demo resources help you explore CloudBridge. No live cloud accounts are connected."}</span></div><span className={liveAWS ? "live-tag" : "simulated-tag"}><span />{liveAWS ? "LIVE AWS" : "SIMULATED DATA"}</span></div>
                  <section className="summary-grid" aria-label="Cloud workspace summary">
                    <SummaryCard label="Total resources" value={summary?.total_resources ?? 0} note="Across all providers" icon={Server} tone="blue" />
                    <SummaryCard label="Active connections" value={summary?.active_connections ?? 0} note="Live and demo accounts" icon={Cloud} tone="cyan" />
                    <SummaryCard label="Security findings" value={summary?.open_findings ?? 0} note="Open findings; demo items labeled" icon={ShieldAlert} tone="amber" />
                    <SummaryCard label="Unread alerts" value={summary?.unread_alerts ?? 0} note="Unacknowledged alerts" icon={Bell} tone="violet" />
                  </section>
                  <section className="content-grid">
                    <article className="panel resource-panel">
                      <div className="panel-heading"><div><h2>Cloud resources</h2><p>Your latest infrastructure inventory</p></div><button className="text-button" onClick={() => navigate("resources")}>View all <ArrowRight size={15} /></button></div>
                      <ResourceTable resources={resources} compact />
                    </article>
                    <article className="panel alerts-panel">
                      <div className="panel-heading"><div><h2>Recent alerts</h2><p>Keep an eye on what needs attention</p></div><button className="icon-button subdued" aria-label="Open alerts" onClick={() => navigate("alerts")}><ExternalLink size={16} /></button></div>
                      <AlertList alerts={alerts} compact onAcknowledge={(id) => updateAlert(id, "acknowledge")} onResolve={(id) => updateAlert(id, "resolve")} />
                      <button className="panel-footer-link" onClick={() => navigate("alerts")}>Go to alert center <ArrowRight size={15} /></button>
                    </article>
                  </section>
                  <section className="insight-strip"><span className="insight-icon"><Shield size={17} /></span><div><strong>Security snapshot</strong><span>{summary?.open_findings ?? 0} simulated findings across your resources. Review each item before connecting live infrastructure.</span></div><button onClick={() => navigate("resources")}>Explore resources <ArrowRight size={15} /></button></section>
                </>
              )}
              {view === "resources" && (
                <>
                  <section className="page-heading"><div><div className="section-kicker">INFRASTRUCTURE INVENTORY</div><h1>Cloud resources</h1><p>Search and filter live infrastructure alongside clearly marked demo resources.</p></div><div className="heading-actions"><button className="secondary-button" onClick={refreshInventory} disabled={!connections.some((connection) => connection.provider === "aws")}><RefreshCw size={15} /> Refresh</button><button className="primary-button" onClick={() => setShowConnectionDialog(true)}><Plus size={17} /> Add connection</button></div></section>
                  {syncMessage && <div className="sync-message" role="status">{syncMessage}</div>}
                  <section className="panel full-panel"><div className="panel-heading table-toolbar"><div><h2>All resources <span className="heading-count">{filteredResources.length}</span></h2><p>Latest successful sync: {formatTimestamp(liveAWS?.last_synced_at)}</p></div><div className="table-filters"><label className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search resources" aria-label="Search resources" /></label><select value={providerFilter} onChange={(event) => setProviderFilter(event.target.value)} aria-label="Filter by provider"><option value="all">All providers</option><option value="aws">AWS</option><option value="azure">Azure</option><option value="gcp">Google Cloud</option></select><select value={regionFilter} onChange={(event) => setRegionFilter(event.target.value)} aria-label="Filter by region"><option value="all">All regions</option>{[...new Set(resources.map((resource) => resource.region))].sort().map((region) => <option key={region}>{region}</option>)}</select></div></div><ResourceTable resources={filteredResources} /></section>
                </>
              )}
              {view === "monitoring" && (
                <>
                  <section className="page-heading"><div><div className="section-kicker">RESOURCE HEALTH</div><h1>Monitoring</h1><p>Metrics are shown only when AWS publishes them; unavailable values are not treated as zero.</p></div><button className="secondary-button" onClick={refreshInventory} disabled={!connections.some((connection) => connection.provider === "aws")}><RefreshCw size={15} /> Refresh metrics</button></section>
                  <div className="sync-message">{liveAWS ? `Latest successful synchronization: ${formatTimestamp(liveAWS.last_synced_at)}` : "Demo Mode: sample inventory has no live metrics."}</div>
                  <section className="panel full-panel"><div className="panel-heading"><div><h2>Monitored resources</h2><p>CloudWatch CPU and explicitly published CWAgent memory metrics</p></div></div><ResourceTable resources={resources} /></section>
                </>
              )}
              {view === "security" && (
                <>
                  <section className="page-heading"><div><div className="section-kicker">READ-ONLY CONFIGURATION ASSESSMENT</div><h1>Security Center</h1><p>Findings reflect observed configurations. Permission failures are reported as incomplete checks, never as secure results.</p></div><button className="primary-button" onClick={runSecurityScan} disabled={scanning || !connections.some((connection) => connection.provider === "aws")}><ShieldAlert size={16} />{scanning ? "Scanning…" : "Run assessment"}</button></section>
                  {Object.keys(scanChecks).length > 0 && <div className="coverage-panel"><strong>Assessment coverage</strong><span>{Object.entries(scanChecks).map(([name, result]) => `${name.replaceAll("_", " ")}: ${result.replaceAll("_", " ")}`).join(" · ")}</span></div>}
                  <section className="summary-grid security-summary">
                    {["critical", "high", "medium", "low", "info"].map((severity) => <SummaryCard key={severity} label={`${formatSeverity(severity)} findings`} value={findings.filter((finding) => finding.status === "open" && finding.severity === severity).length} note="Open findings" icon={ShieldAlert} tone={severity === "critical" || severity === "high" ? "amber" : "cyan"} />)}
                  </section>
                  <section className="panel full-panel"><div className="panel-heading"><div><h2>Security findings <span className="heading-count">{findings.filter((finding) => finding.status === "open").length}</span></h2><p>Recommendations are read-only; CloudBridge does not modify AWS resources.</p></div></div>
                    {findings.length ? <div className="finding-list">{findings.filter((finding) => finding.status === "open").map((finding) => <article className="finding-row" key={finding.id}><span className={`finding-severity severity-${finding.severity}`}>{finding.severity}</span><div className="finding-detail"><strong>{finding.title}</strong><span>{finding.affected_resource} · {finding.simulated ? "Demo finding" : "Live AWS finding"} · {formatTimestamp(finding.detected_at)}</span><p>{finding.description}</p><small>Recommended: {finding.recommendation}</small></div></article>)}</div> : <div className="empty-state"><Shield size={22} /><strong>No findings recorded</strong><span>Run an assessment. Checks that lack AWS permissions will be marked incomplete.</span></div>}
                  </section>
                </>
              )}
              {view === "costs" && (
                <>
                  <section className="page-heading"><div><div className="section-kicker">AWS COST EXPLORER</div><h1>Cost Analytics</h1><p>Billing data is shown only when AWS Cost Explorer permissions and data are available.</p></div><span className={costReport?.simulated ? "simulated-tag" : "live-tag"}><span />{costReport?.simulated ? "DEMO ESTIMATE" : "AWS BILLING DATA"}</span></section>
                  {costError && <div className="page-error" role="alert"><AlertTriangle size={18} /><span>{costError}</span></div>}
                  {costReport ? <>
                    <section className="panel cost-overview"><div><span className="section-kicker">{costReport.simulated ? "SIMULATED MONTHLY ESTIMATE" : "MONTH TO DATE"}</span><strong>{new Intl.NumberFormat(undefined, { style: "currency", currency: costReport.currency }).format(costReport.total)}</strong><small>{costReport.period_start} through {costReport.period_end} · {costReport.estimated ? "Estimated" : "Finalized"}</small></div><span className="cost-total-icon"><DollarSign size={23} /></span></section>
                    <section className="panel full-panel cost-chart"><div className="panel-heading"><div><h2>Spending by AWS service</h2><p>{costReport.simulated ? "Demo values are derived from labeled sample resources." : `Reported in ${costReport.currency}; ${costReport.estimated ? "current estimate" : "finalized period"}.`}</p></div></div>
                      {costReport.services.length ? <div className="cost-service-list">{costReport.services.map((service) => { const width = costReport.total > 0 ? Math.max(2, service.amount / costReport.total * 100) : 0; return <div className="cost-service" key={service.service}><div><strong>{service.service}</strong><span>{new Intl.NumberFormat(undefined, { style: "currency", currency: costReport.currency }).format(service.amount)}</span></div><div className="cost-track"><i style={{ width: `${width}%` }} /></div></div>; })}</div> : <div className="empty-state"><DollarSign size={22} /><strong>No cost details available</strong><span>AWS returned no service-level cost data for this period.</span></div>}
                    </section>
                  </> : !costError && <div className="empty-state"><DollarSign size={22} /><strong>No cost report available</strong><span>Connect an AWS account or use the explicitly labeled demo workspace.</span></div>}
                </>
              )}
              {view === "connections" && (
                <>
                  <section className="page-heading"><div><div className="section-kicker">CLOUD PROVIDERS</div><h1>Connections</h1><p>Manage cloud account records for your workspace.</p></div><button className="primary-button" onClick={() => setShowConnectionDialog(true)}><Plus size={17} /> Add connection</button></section>
                  <div className="demo-banner compact-banner"><span className="demo-banner-icon"><Shield size={16} /></span><div><strong>Connections never store AWS credentials.</strong><span>Live AWS access uses the backend standard credential chain; other providers remain Demo Mode.</span></div><span className="live-tag"><span /> SERVER-SIDE</span></div>
                  <section className="connection-grid">{connections.map((connection) => <article className="panel connection-card" key={connection.id}><div className="connection-card-top"><span className="connection-icon"><Cloud size={20} /></span><span className={`connection-status ${connection.status === "connected" ? "connected" : ""}`}><i />{connection.status}</span></div><h2>{connection.display_name}</h2><p>{formatProvider(connection.provider)}{connection.region ? ` · ${connection.region}` : ""}</p><div className="connection-meta"><span>Account ID</span><strong>{connection.account_identifier || "Not specified"}</strong></div><div className="connection-meta"><span>Data source</span><strong>{connection.simulated ? "Demo Mode" : "Live AWS"}</strong></div><div className="connection-meta"><span>Last successful sync</span><strong>{formatTimestamp(connection.last_synced_at)}</strong></div>{!connection.simulated && <button className="secondary-button connection-refresh" onClick={refreshInventory}><RefreshCw size={14} /> Refresh resources</button>}<div className="connection-footer"><span>{connection.simulated ? "Simulated data" : "Read-only AWS access"}</span><Check size={16} /></div></article>)}<button className="add-connection-card" onClick={() => setShowConnectionDialog(true)}><span><Plus size={20} /></span><strong>Add another account</strong><small>Connect AWS or create a demo record</small></button></section>
                </>
              )}
              {view === "alerts" && (
                <>
                  <section className="page-heading"><div><div className="section-kicker">OPERATIONAL SIGNALS</div><h1>Alert center</h1><p>Security and CPU threshold alerts are persisted in your user-scoped workspace.</p></div><span className="alert-total"><Bell size={16} /> {summary?.unread_alerts ?? 0} unread</span></section>
                  <section className="panel full-panel alerts-full-panel"><div className="panel-heading table-toolbar"><div><h2>{alertStatus === "resolved" ? "Resolved alerts" : "Active alerts"}</h2><p>Most recent activity first</p></div><div className="table-filters"><select value={alertStatus} onChange={(event) => setAlertStatus(event.target.value)} aria-label="Filter by alert status"><option value="active">Active and acknowledged</option><option value="resolved">Resolved</option><option value="all">All statuses</option></select><select value={alertSeverity} onChange={(event) => setAlertSeverity(event.target.value)} aria-label="Filter by alert severity"><option value="all">All severities</option>{["critical", "high", "medium", "low"].map((severity) => <option key={severity} value={severity}>{formatSeverity(severity)}</option>)}<option value="info">Informational</option></select></div></div><AlertList alerts={visibleAlerts} onAcknowledge={(id) => updateAlert(id, "acknowledge")} onResolve={(id) => updateAlert(id, "resolve")} /></section>
                </>
              )}
            </>
          )}
        </div>
        <footer className="app-footer"><span>© {new Date().getFullYear()} CloudBridge</span><span><i /> {liveAWS ? "Live AWS + Demo Mode" : "Simulated workspace"}</span><span>Read-only AWS integration <ArrowDownRight size={13} /></span></footer>
      </main>
      {showConnectionDialog && <ConnectionDialog token={token} onClose={() => setShowConnectionDialog(false)} onCreated={() => { setShowConnectionDialog(false); loadDashboard(token); setView("connections"); }} />}
    </div>
  );
}
