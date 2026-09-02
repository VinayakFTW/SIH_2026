import { useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronUp, CircleDot, FileUp, RefreshCw, Search, ShieldCheck, Sparkles, Wifi } from 'lucide-react'
import { Area, AreaChart, Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import './App.css'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const demoFlows = [
  { flow_id: 'flow-001', metrics: { duration: 0.18, total_fwd_packets: 48, total_bwd_packets: 2, total_length: 3360, packets_per_second: 278, mean_iat: 0.00065, mean_packet_length: 67, bytes_per_second: 18666 }, threat_assessment: { anomaly_score: 0.92, severity: 'Critical', tactic: 'Reconnaissance', technique_id: 'T1046', technique_name: 'Network Service Scanning' } },
  { flow_id: 'flow-002', metrics: { duration: 2.4, total_fwd_packets: 815, total_bwd_packets: 44, total_length: 920000, packets_per_second: 358, mean_iat: 0.0028, mean_packet_length: 1072, bytes_per_second: 383333 }, threat_assessment: { anomaly_score: 0.81, severity: 'High', tactic: 'Impact', technique_id: 'T1498', technique_name: 'Network Denial of Service' } },
  { flow_id: 'flow-003', metrics: { duration: 14.2, total_fwd_packets: 62, total_bwd_packets: 5, total_length: 7400, packets_per_second: 4.7, mean_iat: 0.21, mean_packet_length: 110, bytes_per_second: 521 }, threat_assessment: { anomaly_score: 0.68, severity: 'Medium', tactic: 'Credential Access', technique_id: 'T1110', technique_name: 'Brute Force' } },
  { flow_id: 'flow-004', metrics: { duration: 8.4, total_fwd_packets: 18, total_bwd_packets: 16, total_length: 14200, packets_per_second: 4, mean_iat: 0.24, mean_packet_length: 418, bytes_per_second: 1690 }, threat_assessment: { anomaly_score: 0.31, severity: 'Low', tactic: 'Discovery', technique_id: 'N/A', technique_name: 'Unknown' } },
  { flow_id: 'flow-005', metrics: { duration: 0.06, total_fwd_packets: 11, total_bwd_packets: 0, total_length: 550, packets_per_second: 183, mean_iat: 0.005, mean_packet_length: 50, bytes_per_second: 9166 }, threat_assessment: { anomaly_score: 0.74, severity: 'High', tactic: 'Reconnaissance', technique_id: 'T1046', technique_name: 'Network Service Scanning' } },
]

const colors = { Critical: '#f06b5f', High: '#efaa55', Medium: '#e4c46a', Low: '#55b7a5', Unknown: '#758195' }

function normalizeScore(raw) {
  const score = Number(raw) || 0
  return 1 - Math.exp(-Math.max(score, 0))
}

function firstNumber(...values) {
  const value = values.find((candidate) => candidate !== undefined && candidate !== null)
  return Number(value) || 0
}

function normalizeResults(payload) {
  return (payload?.results || []).map((flow) => {
    const rawMetrics = flow.metrics || {}
    const rawAssessment = flow.threat_assessment || {}
    const rawScore = flow.anomaly_score ?? rawAssessment.anomaly_score

    return {
      ...flow,
      metrics: {
        ...rawMetrics,
        total_fwd_packets: firstNumber(rawMetrics.total_fwd_packets, rawMetrics.tot_fwd_pkts),
        total_bwd_packets: firstNumber(rawMetrics.total_bwd_packets, rawMetrics.tot_bwd_pkts),
        total_bytes: firstNumber(rawMetrics.total_bytes, rawMetrics.total_length),
        duration: firstNumber(rawMetrics.duration, rawMetrics.flow_duration),
      },
      threat_assessment: {
        ...rawAssessment,
        anomaly_score: normalizeScore(rawScore),
      },
    }
  })
}

function formatBytes(value = 0) {
  if (value < 1024) return `${value.toFixed(0)} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 ** 2).toFixed(1)} MB`
}

function reasonFor(flow) {
  const { metrics: m, threat_assessment: t } = flow
  const reasons = [`Anomaly score ${t.anomaly_score.toFixed(3)}, above the 0.50 alert threshold.`]
  if (m.packets_per_second > 500) reasons.push(`Extreme packet rate (${m.packets_per_second.toFixed(0)} pps) indicates aggressive automated traffic.`)
  else if (m.packets_per_second > 100) reasons.push(`Elevated packet rate (${m.packets_per_second.toFixed(0)} pps) is unusual for routine user traffic.`)
  if (m.mean_iat < 0.01) reasons.push(`Rapid packet timing (${(m.mean_iat * 1000).toFixed(2)} ms mean IAT) suggests machine-generated activity.`)
  if (m.total_bwd_packets === 0 && m.total_fwd_packets > 5) reasons.push('Unidirectional traffic has no observed response packets, consistent with probing or a data push.')
  if (t.technique_name && t.technique_name !== 'Unknown') reasons.push(`Telemetry aligns with MITRE ATT&CK ${t.technique_id}: ${t.technique_name}.`)
  return reasons
}

function buildSummary(flows) {
  const anomalies = flows.filter((flow) => (flow.threat_assessment.anomaly_score || 0) > 0.5)
  const anomalyRate = anomalies.length / Math.max(flows.length, 1)
  const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1 }
  const highestSeverity = anomalies.reduce((highest, flow) => {
    const severity = flow.threat_assessment.severity || 'Low'
    return (severityRank[severity] || 0) > (severityRank[highest] || 0) ? severity : highest
  }, 'Low')
  const tactic = Object.entries(anomalies.reduce((acc, flow) => {
    const value = flow.threat_assessment.tactic || 'Unknown'
    acc[value] = (acc[value] || 0) + 1
    return acc
  }, {})).sort((a, b) => b[1] - a[1])[0]
  const technique = Object.entries(anomalies.reduce((acc, flow) => {
    const value = flow.threat_assessment.technique_id || 'N/A'
    acc[value] = (acc[value] || 0) + 1
    return acc
  }, {})).sort((a, b) => b[1] - a[1])[0]
  return { anomalies, anomalyRate, highestSeverity, tactic, technique }
}

function buildThreatData(flows) {
  const anomalies = flows.filter((flow) => (flow.threat_assessment.anomaly_score || 0) > 0.5)
  const countBy = (key) => anomalies.reduce((counts, flow) => {
    const value = flow.threat_assessment[key] || 'Unknown'
    counts[value] = (counts[value] || 0) + 1
    return counts
  }, {})
  return {
    total_flows: flows.length,
    anomalies_detected: anomalies.length,
    benign_flows: flows.length - anomalies.length,
    anomaly_rate: anomalies.length / Math.max(flows.length, 1),
    top_tactics: countBy('tactic'),
    top_techniques: countBy('technique_id'),
    severity_distribution: countBy('severity'),
    max_anomaly_score: Math.max(0, ...flows.map((flow) => flow.threat_assessment.anomaly_score || 0)),
    avg_anomaly_score: flows.reduce((sum, flow) => sum + (flow.threat_assessment.anomaly_score || 0), 0) / Math.max(flows.length, 1),
  }
}

function App() {
  const [flows, setFlows] = useState(() => normalizeResults({ results: demoFlows }))
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('All')
  const [expanded, setExpanded] = useState(null)
  const [loading, setLoading] = useState(false)
  const [source, setSource] = useState('Demo telemetry')
  const [notice, setNotice] = useState('')
  const [activeView, setActiveView] = useState('overview')
  const [groqSummary, setGroqSummary] = useState('')
  const [summaryLoading, setSummaryLoading] = useState(false)

  const anomalies = flows.filter((f) => (f.threat_assessment.anomaly_score || 0) > 0.5)
  const visibleFlows = useMemo(() => flows.filter((flow) => {
    const matchesFilter = filter === 'All' || flow.threat_assessment.severity === filter
    const searchable = `${flow.flow_id} ${flow.threat_assessment.technique_name} ${flow.threat_assessment.tactic}`.toLowerCase()
    return matchesFilter && searchable.includes(query.toLowerCase())
  }), [flows, filter, query])
  const severityData = ['Critical', 'High', 'Medium', 'Low'].map((severity) => ({ name: severity, value: flows.filter((f) => f.threat_assessment.severity === severity).length }))
  const tacticData = Object.entries(flows.reduce((acc, f) => { const key = f.threat_assessment.tactic || 'Unknown'; acc[key] = (acc[key] || 0) + 1; return acc }, {})).map(([name, count]) => ({ name, count }))
  const totalBytes = flows.reduce((sum, f) => sum + (f.metrics.total_length || 0), 0)
  const criticalCount = flows.filter((f) => ['Critical', 'High'].includes(f.threat_assessment.severity)).length
  const summary = buildSummary(flows)
  const scoreData = flows.map((flow, index) => ({ name: flow.flow_id || `flow-${index + 1}`, score: Number((flow.threat_assessment.anomaly_score || 0).toFixed(3)) }))
  const trafficData = flows.map((flow) => ({ name: flow.flow_id, packets: Number((flow.metrics.packets_per_second || 0).toFixed(1)), bytes: Number(((flow.metrics.bytes_per_second || 0) / 1024).toFixed(1)) }))
  const displayedFlows = activeView === 'alerts' ? visibleFlows.filter((flow) => (flow.threat_assessment.anomaly_score || 0) > 0.5) : visibleFlows
  const summaryFinding = summary.anomalies.length === 0
    ? 'No flow crossed the alert threshold in this analysis window.'
    : `${summary.anomalies.length} of ${flows.length} flows exceeded the 0.50 anomaly threshold (${(summary.anomalyRate * 100).toFixed(1)}%). ${summary.highestSeverity} is the highest priority observed, led by ${summary.tactic?.[0] || 'mixed tactics'}.`
  const summaryDetail = summary.anomalies.length === 0
    ? 'Telemetry remains within the current baseline. Continue monitoring for changes in packet timing, volume, and directional balance.'
    : `The most frequent technique is ${summary.technique?.[0] || 'not yet classified'}. Prioritize source validation, correlate these flows with endpoint and authentication events, and preserve the relevant JSON or packet evidence before containment.`
  const viewCopy = {
    overview: ['Threat overview', 'Executive posture across the loaded inference results.'],
    alerts: ['Alert queue', 'Review only flows that crossed the anomaly threshold and prioritize response.'],
  }[activeView]

  async function generateGroqSummary(currentFlows = flows) {
    setSummaryLoading(true)
    setNotice('Generating Groq executive summary...')
    try {
      const response = await fetch(`${API_URL}/api/v1/summarize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildThreatData(currentFlows)),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || 'Summary request failed')
      setGroqSummary(data.summary)
      setNotice(`Groq summary generated with ${data.model}.`)
    } catch (error) {
      setNotice(`Groq summary unavailable: ${error.message}`)
    } finally { setSummaryLoading(false) }
  }

  async function uploadJson(event) {
    const file = event.target.files?.[0]
    if (!file) return
    setLoading(true); setNotice('Reading inference results...')
    try {
      if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) {
        setNotice('Uploading and analyzing PCAP file...')
        const formData = new FormData()
        formData.append('file', file)
        
        const response = await fetch(`${API_URL}/api/v1/forecast/pcap`, {
          method: 'POST',
          body: formData,
        })
        
        const data = await response.json()
        if (!response.ok) throw new Error(data.detail || 'PCAP analysis failed')
        if (!Array.isArray(data.results)) throw new Error('Invalid results')
        const parsedFlows = normalizeResults(data)
        setFlows(parsedFlows); setGroqSummary(''); setSource(file.name); setNotice(`${parsedFlows.length} flows loaded from ${file.name}.`)
      } else {
        const data = JSON.parse(await file.text())
        if (!Array.isArray(data.results)) throw new Error('Invalid results')
        const parsedFlows = normalizeResults(data)
        setFlows(parsedFlows); setGroqSummary(''); setSource(file.name); setNotice(`${parsedFlows.length} flows loaded from ${file.name}.`)
      }
    } catch (error) { setNotice(`Failed to load file: ${error.message || 'Invalid format.'}`) }
    finally { setLoading(false); event.target.value = '' }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><ShieldCheck size={22} /></div><div><strong>ROGUE KERNEL</strong><span>NETWORK DEFENSE</span></div></div>
      <div className="rail-label">WORKSPACE</div>
      <nav><button className={`nav-item ${activeView === 'overview' ? 'active' : ''}`} onClick={() => setActiveView('overview')}><CircleDot size={16} /> Threat overview</button><button className={`nav-item ${activeView === 'alerts' ? 'active' : ''}`} onClick={() => setActiveView('alerts')}><AlertTriangle size={16} /> Alert queue <b>{anomalies.length}</b></button></nav>
      <div className="sidebar-bottom"><div className="system-status"><span className="status-dot" /> Engine operational</div><small>v0.1.0 · local instance</small></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><p className="eyebrow">ROGUE KERNEL / SECURITY OPERATIONS CENTER</p><h1>{viewCopy[0]}</h1><p className="subhead">{viewCopy[1]}</p></div><div className="top-actions"><span className="connection"><span className="status-dot" /> {source}</span><label className="upload-button"><FileUp size={16} /> Load Data<input type="file" accept=".json,application/json,.pcap,.pcapng" onChange={uploadJson} /></label><button className="icon-button" title="Reload demo telemetry" onClick={() => { setFlows(demoFlows); setSource('Demo telemetry'); setNotice('Demo telemetry restored.') }}><RefreshCw size={17} className={loading ? 'spin' : ''} /></button></div></header>
      {notice && <div className="notice"><span>{notice}</span><button onClick={() => setNotice('')}>Dismiss</button></div>}
      <div className="groq-actions"><button className="secondary-button" onClick={() => generateGroqSummary()} disabled={summaryLoading}><Sparkles size={15} /> {summaryLoading ? 'Generating...' : 'Generate Groq summary'}</button>{groqSummary && <span>Server-side analysis · Groq</span>}</div>
      {groqSummary && <section className="groq-summary"><div className="groq-heading"><Sparkles size={17} /><strong>Groq analyst narrative</strong><span>openai/gpt-oss-20b</span></div><div className="groq-copy"><ReactMarkdown remarkPlugins={[remarkGfm]}>{groqSummary}</ReactMarkdown></div></section>}
      <section className="metrics-grid"><Metric label="Flows observed" value={flows.length} detail="current analysis window" icon={<Wifi size={17} />} /><Metric label="Priority alerts" value={criticalCount} detail={`${anomalies.length} total anomalies`} tone="danger" icon={<AlertTriangle size={17} />} /><Metric label="Avg anomaly score" value={(flows.reduce((s, f) => s + (f.threat_assessment.anomaly_score || 0), 0) / Math.max(flows.length, 1)).toFixed(3)} detail="distance-from-normal measure" icon={<CircleDot size={17} />} /><Metric label="Data inspected" value={formatBytes(totalBytes)} detail="across all flows" icon={<ShieldCheck size={17} />} /></section>
      <section className={`summary-panel ${summary.highestSeverity.toLowerCase()}`}><div className="summary-icon"><AlertTriangle size={19} /></div><div><div className="summary-title"><span>Executive anomaly summary</span><strong>{summary.highestSeverity} PRIORITY</strong></div><ul className="summary-list"><li>{summaryFinding}</li><li>{summaryDetail}</li><li>{summary.anomalies.length ? `Response posture: begin with ${summary.highestSeverity.toLowerCase()} alerts, validate affected hosts, and compare against known maintenance or scanning activity.` : 'Response posture: no immediate containment is indicated; keep the current baseline under observation.'}</li></ul><div className="summary-actions"><span>Recommended focus: {summary.anomalies.length ? 'validate source context · correlate alerts · preserve evidence' : 'continue baseline monitoring'}</span></div></div></section>
      <section className="chart-grid"><Panel title="Severity distribution" meta="FLOW COUNT"><div className="chart-wrap"><ResponsiveContainer width="100%" height={220}><PieChart><Pie data={severityData} dataKey="value" nameKey="name" innerRadius={62} outerRadius={84} paddingAngle={4}>{severityData.map((entry) => <Cell key={entry.name} fill={colors[entry.name]} />)}</Pie><Tooltip isAnimationActive={false} content={<ChartTooltip />} /></PieChart></ResponsiveContainer><div className="legend">{severityData.map((item) => <div key={item.name}><span style={{ background: colors[item.name] }} />{item.name}<b>{item.value}</b></div>)}</div></div></Panel><Panel title="MITRE tactics" meta="TOP SIGNALS"><ResponsiveContainer width="100%" height={220}><BarChart data={tacticData} layout="vertical" margin={{ left: 12, right: 16 }}><XAxis type="number" hide /><YAxis dataKey="name" type="category" width={112} tick={{ fill: '#8d9aae', fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip isAnimationActive={false} content={<ChartTooltip />} /><Bar dataKey="count" fill="#57b9aa" radius={[0, 3, 3, 0]} barSize={16} /></BarChart></ResponsiveContainer></Panel></section>
      <section className="chart-grid secondary-charts"><Panel title="Anomaly score by flow" meta="DISTANCE FROM NORMAL"><ResponsiveContainer width="100%" height={220}><AreaChart data={scoreData} margin={{ top: 8, right: 8, bottom: 4, left: -18 }}><defs><linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#efaa55" stopOpacity={0.42} /><stop offset="100%" stopColor="#efaa55" stopOpacity={0.02} /></linearGradient></defs><XAxis dataKey="name" tick={{ fill: '#758195', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis domain={[0, 1]} tick={{ fill: '#758195', fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip isAnimationActive={false} content={<ChartTooltip />} /><Area type="monotone" dataKey="score" stroke="#efaa55" fill="url(#scoreFill)" strokeWidth={2} /></AreaChart></ResponsiveContainer></Panel><Panel title="Traffic intensity" meta="HOVER TO INSPECT"><ResponsiveContainer width="100%" height={220}><BarChart data={trafficData} margin={{ top: 8, right: 8, bottom: 4, left: -18 }}><XAxis dataKey="name" tick={{ fill: '#758195', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis yAxisId="left" tick={{ fill: '#758195', fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip isAnimationActive={false} content={<ChartTooltip />} /><Bar yAxisId="left" dataKey="packets" name="Packets/sec" fill="#57b9aa" radius={[3, 3, 0, 0]} barSize={20} /></BarChart></ResponsiveContainer></Panel></section>
      <section className="panel table-panel"><div className="panel-heading"><div><h2>{activeView === 'alerts' ? 'Alert queue' : activeView === 'telemetry' ? 'Live telemetry' : 'Flow evidence'}</h2><span className="panel-caption">{activeView === 'alerts' ? 'Anomalous flows requiring analyst review' : activeView === 'telemetry' ? 'Current JSON analysis window · refresh by loading another file' : 'Prioritized network sessions and model rationale'}</span></div><div className="table-tools"><div className="search"><Search size={15} /><input placeholder="Search flow or technique" value={query} onChange={(e) => setQuery(e.target.value)} /></div><select value={filter} onChange={(e) => setFilter(e.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></div></div><div className="table-scroll"><table><thead><tr><th>Flow ID</th><th>Score</th><th>Severity</th><th>ATT&amp;CK technique</th><th>Tactic</th><th>Traffic profile</th><th /></tr></thead><tbody>{displayedFlows.map((flow) => { const t = flow.threat_assessment; const m = flow.metrics; const isOpen = expanded === flow.flow_id; return <tr key={flow.flow_id} className={isOpen ? 'expanded-row' : ''}><td><button className="flow-id" onClick={() => setExpanded(isOpen ? null : flow.flow_id)}>{isOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}{flow.flow_id}</button>{isOpen && <div className="reasoning"><strong>Analyst reasoning</strong>{reasonFor(flow).map((reason) => <p key={reason}><span>•</span>{reason}</p>)}</div>}</td><td><span className="score">{(t.anomaly_score || 0).toFixed(3)}</span></td><td><span className="severity" style={{ color: colors[t.severity] }}>{t.severity || 'Unknown'}</span></td><td><strong>{t.technique_id || 'N/A'}</strong><small>{t.technique_name || 'Unknown'}</small></td><td>{t.tactic || 'Unknown'}</td><td><span>{m.packets_per_second?.toFixed(1) || 0} pps</span><small>{formatBytes(m.total_length || 0)}</small></td><td><button className="inspect" onClick={() => setExpanded(isOpen ? null : flow.flow_id)}>{isOpen ? 'Close' : 'Inspect'}</button></td></tr> })}</tbody></table></div>{displayedFlows.length === 0 && <div className="empty">No flows match the current view or filter.</div>}</section>
      <footer><span><CheckCircle2 size={14} /> Inference pipeline ready</span><span>Last refreshed just now</span></footer>
    </main>
  </div>
}

function Metric({ label, value, detail, icon, tone = '' }) { return <div className={`metric ${tone}`}><div className="metric-icon">{icon}</div><div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div></div> }
function Panel({ title, meta, children }) { return <div className="panel"><div className="panel-heading"><div><h2>{title}</h2></div><span className="panel-meta">{meta}</span></div>{children}</div> }
function ChartTooltip({ active, payload }) { if (!active || !payload?.length) return null; return <div className="chart-tooltip"><b>{payload[0].name}</b><span>{payload[0].value} flows</span></div> }

export default App
