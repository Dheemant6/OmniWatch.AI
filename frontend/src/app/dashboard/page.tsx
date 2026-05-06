'use client';

import React, { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import styles from './dashboard.module.css';

const API_BASE_URL = 'http://127.0.0.1:8000/api/v1';
const WS_BASE_URL = 'ws://127.0.0.1:8000/api/v1';

export default function Dashboard() {
  const [authToken, setAuthToken] = useState<string>('');
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(true);
  const [loginUser, setLoginUser] = useState<string>('');
  const [loginPass, setLoginPass] = useState<string>('');
  const [loginError, setLoginError] = useState<string>('');

  const [activeTab, setActiveTab] = useState('Overview');
  const [status, setStatus] = useState<any>(null);
  const [tasks, setTasks] = useState<any[]>([]);
  const [insights, setInsights] = useState<any>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [repoUrl, setRepoUrl] = useState<string>('');
  const [isTriggering, setIsTriggering] = useState<boolean>(false);
  const [expandedFindingIdx, setExpandedFindingIdx] = useState<number | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  const logsContainerRef = useRef<HTMLDivElement>(null);
  const [isAutoScroll, setIsAutoScroll] = useState(true);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let token = sessionStorage.getItem("omniwatch_auth");
    if (token) {
        setAuthToken(token);
        setIsLoggingIn(false);
    }
  }, []);

  const handleLoginSubmit = (e: React.FormEvent) => {
      e.preventDefault();
      if (loginUser && loginPass) {
          const token = window.btoa(`${loginUser}:${loginPass}`);
          sessionStorage.setItem("omniwatch_auth", token);
          setAuthToken(token);
          setIsLoggingIn(false);
          setLoginError("");
      } else {
          setLoginError("Please enter both username and password.");
      }
  };

  const getHeaders = () => ({ 'Authorization': `Basic ${authToken}` });

  const fetchStatus = async () => {
    if (!authToken) return;
    try {
        const res = await fetch(`${API_BASE_URL}/system/status`, { headers: getHeaders() });
        if (res.ok) {
            setStatus(await res.json());
        } else if (res.status === 401) {
            sessionStorage.removeItem("omniwatch_auth");
            setAuthToken("");
            setIsLoggingIn(true);
            setLoginError("Invalid credentials.");
        }
    } catch(err) {
        console.error("Failed to fetch status", err);
    }
  };

  const fetchTasks = async () => {
    if (!authToken) return;
    try {
        const res = await fetch(`${API_BASE_URL}/system/tasks`, { headers: getHeaders() });
        if (res.ok) {
            const data = await res.json();
            setTasks(data.tasks || []);
        }
    } catch(err) {
        console.error("Failed to fetch tasks", err);
    }
  };

  const handleAbort = async (taskId: string) => {
    if (!authToken) return;
    try {
        await fetch(`${API_BASE_URL}/system/tasks/${taskId}`, { 
            method: 'DELETE',
            headers: getHeaders() 
        });
        fetchTasks();
    } catch (err) {
        console.error(err);
    }
  };

  const fetchInsights = async () => {
    if (!authToken) return;
    try {
        const res = await fetch(`${API_BASE_URL}/system/insights`, { headers: getHeaders() });
        if (res.ok) {
            setInsights(await res.json());
        }
    } catch(err) {
        console.error("Failed to fetch insights", err);
    }
  };

  const clearScanResults = async () => {
    if (!authToken) return;
    if (!window.confirm('⚠️ This will permanently delete ALL scan results and vulnerability history from the database. Continue?')) return;
    try {
        const res = await fetch(`${API_BASE_URL}/system/clear`, { method: 'DELETE', headers: getHeaders() });
        if (res.ok) {
            setInsights(null);
            setTasks([]);
            alert('✅ All scan results cleared successfully.');
            fetchInsights();
        } else {
            alert('Failed to clear scan results.');
        }
    } catch(err) {
        console.error(err);
        alert('Error clearing scan results.');
    }
  };

  const triggerManualScan = async () => {
    if (!authToken || !repoUrl) return;
    setIsTriggering(true);
    
    const urls = repoUrl.split(/[\n,]+/).map(u => u.trim()).filter(u => u.length > 0);
    if (urls.length === 0) {
        setIsTriggering(false);
        return;
    }

    try {
        let successCount = 0;
        for (const url of urls) {
            const res = await fetch(`${API_BASE_URL}/system/scan`, { 
                method: 'POST',
                headers: {
                    ...getHeaders(),
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ repo_url: url })
            });
            if (res.ok) successCount++;
        }
        
        if (successCount > 0) {
            alert(`Successfully triggered ${successCount} pipeline(s)! Check Active Tasks and System Logs.`);
            setActiveTab('Tasks');
            fetchTasks();
        } else {
            alert('Failed to trigger scans.');
        }
    } catch(err) {
        console.error(err);
        alert('Error triggering scan.');
    } finally {
        setIsTriggering(false);
    }
  };

  const handleExport = (format: string, reportType: 'full' | 'repo_scan' | 'sca' = 'full') => {
      const findings = insights?.all_findings || insights?.recent_findings || [];
      const sbom_data = insights?.sbom || [];
      const scans = insights?.recent_scans || [];
      const metrics = insights?.metrics || {};
      let content = '';

      if (format === 'csv') {
          // Section 1: Metrics
          content += 'OmniWatch Security Report\n';
          content += `Generated,${new Date().toLocaleString()}\n\n`;
          content += 'PIPELINE ANALYTICS\n';
          content += `Total Scans Run,${metrics.total_scans_run || 0}\n`;
          content += `Critical,${metrics.critical || 0}\n`;
          content += `High,${metrics.high || 0}\n`;
          content += `Medium,${metrics.medium || 0}\n`;
          content += `Low,${metrics.low || 0}\n`;
          content += `Remediation Rate,${metrics.remediation_rate || '0%'}\n\n`;

          // Section 2: Pipeline History
          content += 'PIPELINE SCAN HISTORY\n';
          content += 'Scan ID,Repository,Status,Started At,Completed At\n';
          scans.forEach((s: any) => {
              content += `${s.id},"${s.repo_url}",${s.status},"${s.created_at || ''}","${s.completed_at || ''}"\n`;
          });

          // Section 3: Findings
          content += '\nSECURITY FINDINGS\n';
          content += 'Severity,CVE,Vulnerability,Component,Status,Remediation Patch\n';
          findings.forEach((item: any) => {
              const patch_csv = item.patch ? `"${String(item.patch).replace(/"/g, '""').replace(/\n/g, ' | ')}"` : '""';
              const cve_csv = item.cve ? `"${item.cve}"` : '"N/A"';
              content += `"${item.sev}",${cve_csv},"${item.vuln}","${item.comp}","${item.stat}",${patch_csv}\n`;
          });

          // Section 4: SBOM
          if (sbom_data.length > 0) {
              content += '\nSOFTWARE BILL OF MATERIALS (SBOM)\n';
              content += 'Component Name,Version,Type\n';
              sbom_data.forEach((item: any) => {
                  content += `"${item.name}","${item.version}","${item.type}"\n`;
              });
          }

          const blob = new Blob([content], { type: 'text/csv' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'omniwatch_report.csv';
          a.click();

      } else if (format === 'word') {
          const ts = new Date().toLocaleString();
          const titleType = reportType === 'repo_scan' ? 'Repo Scan Analysis' : reportType === 'sca' ? 'SCA' : 'Security';
          content = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
          <head><title>OmniWatch ${titleType} Report</title></head><body style="font-family: sans-serif; color: #111;">
          <h1 style="color: #7c3aed;">OmniWatch ${titleType} Report</h1>
          <p style="color: #555;">Generated: ${ts}</p><hr/>`;

          if (reportType === 'full' || reportType === 'repo_scan') {
              content += `<h2>Pipeline Analytics</h2>
              <table border="1" cellpadding="6" style="border-collapse:collapse; width:100%;">
              <tr><th style="background:#f4f4f4;">Metric</th><th style="background:#f4f4f4;">Value</th></tr>
              <tr><td>Total Scans Run</td><td>${metrics.total_scans_run || 0}</td></tr>
              <tr><td>Critical</td><td>${metrics.critical || 0}</td></tr>
              <tr><td>High</td><td>${metrics.high || 0}</td></tr>
              <tr><td>Medium</td><td>${metrics.medium || 0}</td></tr>
              <tr><td>Low</td><td>${metrics.low || 0}</td></tr>
              <tr><td>Remediation Rate</td><td>${metrics.remediation_rate || '0%'}</td></tr>
              </table>

              <h2>Pipeline Scan History</h2>
              <table border="1" cellpadding="6" style="border-collapse:collapse; width:100%;">
              <tr><th style="background:#f4f4f4;">Scan ID</th><th style="background:#f4f4f4;">Repository</th><th style="background:#f4f4f4;">Status</th><th style="background:#f4f4f4;">Started At</th><th style="background:#f4f4f4;">Completed At</th></tr>`;
              scans.forEach((s: any) => {
                  content += `<tr><td>${s.id}</td><td>${s.repo_url}</td><td>${s.status}</td><td>${s.created_at || ''}</td><td>${s.completed_at || '---'}</td></tr>`;
              });
              content += `</table>`;

              content += `<h2>Detailed Security Findings</h2>`;
              if (findings.length === 0) {
                  content += `<p>No security findings reported.</p>`;
              }
              findings.forEach((item: any, idx: number) => {
                  const patch_html = item.patch ? `<pre style="background:#f4f4f4;padding:8px;font-size:0.8em;white-space:pre-wrap; border-radius: 4px;">${item.patch.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>` : '<p style="color:#777;">No patch available.</p>';
                  const cve_html = item.cve ? `<a href="https://nvd.nist.gov/vuln/detail/${item.cve}" style="color: #bc13fe;">${item.cve}</a>` : 'N/A';
                  const cwe_html = item.cwe ? ` | <strong>CWE:</strong> ${item.cwe}` : '';
                  const titleColor = item.sev === 'Critical' ? '#bc13fe' : item.sev === 'High' ? '#ef4444' : item.sev === 'Med' ? '#f59e0b' : '#10b981';
                  
                  content += `
                  <div style="border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 8px;">
                      <h3 style="margin-top: 0; color: ${titleColor};">
                          [${item.sev}] ${item.vuln}
                      </h3>
                      <p style="margin: 5px 0;"><strong>Component:</strong> <span style="font-family: monospace; background: #f0f0f0; padding: 2px 4px; border-radius: 3px;">${item.comp}</span></p>
                      <p style="margin: 5px 0;"><strong>Status:</strong> ${item.stat}</p>
                      <p style="margin: 5px 0;"><strong>References:</strong> CVE: ${cve_html}${cwe_html}</p>
                      
                      <div style="background: #f9f9f9; padding: 12px; margin: 15px 0; border-left: 4px solid ${titleColor}; border-radius: 0 4px 4px 0;">
                          <h4 style="margin-top: 0; color: #333;">Impact & Description</h4>
                          <p style="margin-bottom: 0; color: #555;">${item.description || 'Detailed impact description not available for this finding.'}</p>
                      </div>
                      
                      <div style="background: #fdfdfd; padding: 12px; border-left: 4px solid #00f0ff; border-radius: 0 4px 4px 0;">
                          <h4 style="margin-top: 0; color: #333;">What needs to be changed (Remediation)</h4>
                          ${patch_html}
                      </div>
                  </div>`;
              });
          }

          if (reportType === 'full' || reportType === 'sca') {
              content += `<h2>Supply Chain Analysis (SCA) & Software Bill of Materials (SBOM)</h2>`;
              if (sbom_data.length > 0) {
                  content += `
                  <table border="1" cellpadding="6" style="border-collapse:collapse; width:100%;">
                  <tr><th style="background:#f4f4f4;">Component Name</th><th style="background:#f4f4f4;">Version</th><th style="background:#f4f4f4;">Type</th></tr>`;
                  sbom_data.forEach((item: any) => {
                      content += `<tr><td>${item.name}</td><td>${item.version}</td><td style="text-transform: capitalize;">${item.type}</td></tr>`;
                  });
                  content += `</table>`;
              } else {
                  content += `<p>No SBOM data available for the recent scans.</p>`;
              }
          }

          content += `</body></html>`;
          const blob = new Blob([content], { type: 'application/msword;charset=utf-8' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `omniwatch_${reportType}_report.doc`;
          a.click();

      } else if (format === 'pdf') {
          window.print();
      }
  };

  useEffect(() => {
    if (!authToken) return;
    fetchStatus();
    fetchTasks();
    fetchInsights();
    
    // Polling every 5 seconds for status and tasks
    const interval = setInterval(() => {
        fetchStatus();
        fetchTasks();
        fetchInsights();
    }, 5000);

    return () => clearInterval(interval);
  }, [authToken]);

  useEffect(() => {
    if (!authToken) return;
    // Connect WebSocket for Logs
    const connectLogsStream = () => {
        if (wsRef.current) return;
        
        const ws = new WebSocket(`${WS_BASE_URL}/system/ws/logs?token=${authToken}`);
        
        ws.onopen = () => {
            console.log('Log stream connected');
        };
        
        ws.onmessage = (event) => {
            const line = event.data;
            if (line.includes('[PIPELINE_STAGE]') || line.includes('[ERROR]')) {
                setLogs(prev => [...prev, line].slice(-200));
            }
        };
        
        ws.onclose = () => {
            console.log('Log stream disconnected, retrying in 5s...');
            wsRef.current = null;
            setTimeout(connectLogsStream, 5000);
        };
        
        ws.onerror = (err) => {
            console.error("WebSocket Error:", err);
            ws.close();
        };

        wsRef.current = ws;
    };

    connectLogsStream();

    return () => {
        if (wsRef.current) {
            wsRef.current.close();
            wsRef.current = null;
        }
    };
  }, [authToken]);

  const handleScroll = () => {
      if (!logsContainerRef.current) return;
      const { scrollTop, scrollHeight, clientHeight } = logsContainerRef.current;
      // Consider "at bottom" if within 50px
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
      setIsAutoScroll(isAtBottom);
  };

  useEffect(() => {
    // Auto-scroll logs only if user is at the bottom
    if (isAutoScroll && logEndRef.current) {
        logEndRef.current.scrollIntoView();
    }
  }, [logs, isAutoScroll]);

  const renderLogLine = (line: string, i: number) => {
      let colorClass = styles.logText;
      if (line.includes('[INFO]')) colorClass = styles.logInfo;
      if (line.includes('[WARN]')) colorClass = styles.logWarn;
      if (line.includes('[ERROR]')) colorClass = styles.logError;

      // Ensure we safely display if format is missing brackets
      const parts = line.split(/(\[.*?\])/);
      if (parts.length < 3) {
          return <p key={i} className={styles.logLine}>{line}</p>;
      }
      
      return (
          <p key={i} className={styles.logLine}>
            {parts[0]} <span className={colorClass}>{parts[1]}</span> {parts.slice(2).join('')}
          </p>
      );
  };

  if (isLoggingIn || !authToken) {
      return (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: 'var(--bg-dark)', fontFamily: 'var(--font-sans)', position: 'relative', overflow: 'hidden' }}>
              {/* Background Orbs to match landing */}
              <div className="glow-orb purple" style={{ top: '10%', left: '20%' }}></div>
              <div className="glow-orb cyan" style={{ bottom: '10%', right: '20%' }}></div>
              
              <div className="glass-panel" style={{ padding: '40px', borderRadius: '24px', width: '100%', maxWidth: '400px', zIndex: 10, display: 'flex', flexDirection: 'column', alignItems: 'center', background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(16px)' }}>
                  <style>
                  {`
                    @keyframes radiate {
                      0% { text-shadow: 0 0 5px rgba(188, 19, 254, 0.2), 0 0 10px rgba(188, 19, 254, 0.2); }
                      50% { text-shadow: 0 0 20px rgba(188, 19, 254, 0.8), 0 0 40px rgba(0, 240, 255, 0.8), 0 0 60px rgba(188, 19, 254, 0.5); }
                      100% { text-shadow: 0 0 5px rgba(188, 19, 254, 0.2), 0 0 10px rgba(188, 19, 254, 0.2); }
                    }
                  `}
                  </style>
                  <div style={{ fontSize: '2rem', fontWeight: '900', marginBottom: '8px', letterSpacing: '2px', animation: 'radiate 3s infinite ease-in-out', color: 'white' }}>
                      OMNIWATCH<span className="text-gradient">.AI</span>
                  </div>
                  <h2 style={{ marginBottom: '24px', color: 'var(--text-muted)', fontSize: '1rem', fontWeight: 'normal' }}>Dashboard Login</h2>
                  
                  <form onSubmit={handleLoginSubmit} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      {loginError && <div style={{ color: '#ef4444', fontSize: '0.85rem', textAlign: 'center', background: 'rgba(239, 68, 68, 0.1)', padding: '8px', borderRadius: '8px' }}>{loginError}</div>}
                      
                      <div>
                          <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Username</label>
                          <input 
                              type="text" 
                              value={loginUser}
                              onChange={(e) => setLoginUser(e.target.value)}
                              style={{ width: '100%', padding: '12px', borderRadius: '12px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', color: 'white', outline: 'none' }}
                              placeholder="e.g. admin"
                          />
                      </div>
                      <div>
                          <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Password</label>
                          <input 
                              type="password" 
                              value={loginPass}
                              onChange={(e) => setLoginPass(e.target.value)}
                              style={{ width: '100%', padding: '12px', borderRadius: '12px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', color: 'white', outline: 'none' }}
                              placeholder="••••••••"
                          />
                      </div>
                      
                      <button 
                          type="submit" 
                          className="btn-primary" 
                          style={{ width: '100%', marginTop: '16px', padding: '12px', borderRadius: '12px', border: 'none', cursor: 'pointer', fontWeight: 'bold', background: 'linear-gradient(90deg, var(--neon-purple), var(--neon-cyan))', color: 'white' }}>
                          Authenticate
                      </button>
                      
                      <Link href="/" style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', marginTop: '16px', textDecoration: 'none', alignSelf: 'center' }} onMouseOver={(e) => e.currentTarget.style.color = 'var(--neon-cyan)'} onMouseOut={(e) => e.currentTarget.style.color = 'var(--text-muted)'}>
                          ← Back to Home
                      </Link>
                  </form>
              </div>
          </div>
      );
  }

  return (
    <div className={styles.dashboardContainer}>
      {/* Sidebar */}
      <aside className={styles.sidebar}>
        <div className={`${styles.logo} text-gradient-purple`}>
           OmniWatch Admin
        </div>
        <div 
           className={`${styles.navItem} ${activeTab === 'Overview' ? styles.active : ''}`}
           onClick={() => setActiveTab('Overview')}
        >
          <span style={{marginRight: '8px'}}>📊</span> Overview
        </div>
        <div 
           className={`${styles.navItem} ${activeTab === 'Tasks' ? styles.active : ''}`}
           onClick={() => setActiveTab('Tasks')}
        >
          <span style={{marginRight: '8px'}}>⚡</span> Active Tasks
        </div>
        <div 
           className={`${styles.navItem} ${activeTab === 'Logs' ? styles.active : ''}`}
           onClick={() => setActiveTab('Logs')}
        >
          <span style={{marginRight: '8px'}}>📝</span> System Logs
          <span style={{display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: wsRef.current?.readyState === 1 ? '#10b981' : '#f59e0b', marginLeft: '8px'}}></span>
        </div>
        <div 
           className={`${styles.navItem} ${activeTab === 'Config' ? styles.active : ''}`}
           onClick={() => setActiveTab('Config')}
        >
          <span style={{marginRight: '8px'}}>⚙️</span> Config
        </div>
        <div 
           className={`${styles.navItem} ${activeTab === 'Insights' ? styles.active : ''}`}
           onClick={() => setActiveTab('Insights')}
        >
          <span style={{marginRight: '8px'}}>📈</span> Insights
        </div>
      </aside>

      {/* Main Content */}
      <main className={styles.mainContent}>
        <div className={styles.header}>
            <h1 className={styles.headerTitle}>{activeTab}</h1>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div className={`glass-panel`} style={{padding: '8px 16px', borderRadius: '20px', fontSize: '0.9rem', display: 'flex', gap: '16px'}}>
                   <span>User: <span style={{color: 'var(--neon-purple)', fontWeight: 'bold'}}>{status?.user || '---'}</span></span>
                   <span>Status: <span style={{color: status?.status === 'Healthy' ? '#10b981' : '#ef4444', fontWeight: 'bold'}}>{status?.status || 'Unknown'}</span></span>
                </div>
                <div 
                   onClick={() => {
                       sessionStorage.removeItem("omniwatch_auth");
                       window.location.href = "/";
                   }}
                   className="glass-panel"
                   style={{ 
                       padding: '8px 16px', 
                       borderRadius: '20px', 
                       color: '#ef4444', 
                       textDecoration: 'none', 
                       fontSize: '0.9rem', 
                       fontWeight: '500', 
                       transition: 'all 0.3s ease',
                       display: 'flex',
                       alignItems: 'center',
                       gap: '8px',
                       cursor: 'pointer'
                   }} 
                   onMouseOver={(e) => { e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)'; e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.4)'; e.currentTarget.style.boxShadow = '0 0 15px rgba(239, 68, 68, 0.2)'; }} 
                   onMouseOut={(e) => { e.currentTarget.style.background = ''; e.currentTarget.style.borderColor = ''; e.currentTarget.style.boxShadow = ''; }}
                >
                    <span style={{ fontSize: '1rem', marginTop: '-2px' }}>🚪</span> Logout
                </div>
            </div>
        </div>

        {(activeTab === 'Overview' || activeTab === 'Tasks') && (
            <>
                <div className={styles.statsGrid}>
                    <div className={`${styles.statCard} glass-panel`}>
                        <span className={styles.statLabel}>Active Scans</span>
                        <span className={`${styles.statValue} text-gradient-purple`}>{tasks.filter(t => t.status === 'Active').length}</span>
                        <span className={`${styles.statStatus} ${styles.success}`}>Running smoothly</span>
                    </div>
                    <div className={`${styles.statCard} glass-panel`}>
                        <span className={styles.statLabel}>Redis Connection</span>
                        <span className={`${styles.statValue} text-gradient`}>{status ? 'Connected' : '---'}</span>
                        <span className={`${styles.statStatus} ${status?.redis === 'Connected' ? styles.success : styles.warning}`}>{status?.redis || 'Checking...'}</span>
                    </div>
                    <div className={`${styles.statCard} glass-panel`}>
                        <span className={styles.statLabel}>Celery Workers</span>
                        <span className={`${styles.statValue} text-gradient`}>{status?.worker_status === 'Online' ? 'Active' : status?.worker_status === 'Busy (Scanning)' ? 'Busy' : 'Offline'}</span>
                        <span className={`${styles.statStatus} ${status?.worker_status === 'Online' ? styles.success : status?.worker_status === 'Busy (Scanning)' ? styles.warning : styles.error}`}>{status?.worker_status || 'Unknown'}</span>
                    </div>
                </div>

                <div className={`glass-panel`} style={{padding: '24px', marginTop: '16px'}}>
                    <h2 className={styles.sectionTitle}>Process Monitor</h2>
                    {tasks.length === 0 ? (
                        <p style={{color: 'var(--text-muted)'}}>No active tasks running.</p>
                    ) : (
                        <table className={styles.processList}>
                            <thead>
                                <tr>
                                    <th>Task ID</th>
                                    <th>Repository</th>
                                    <th>Current Stage</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <style>
                                {`
                                  @keyframes pulseDot {
                                    0% { transform: scale(0.95); opacity: 0.5; }
                                    50% { transform: scale(1); opacity: 1; box-shadow: 0 0 8px var(--neon-cyan); }
                                    100% { transform: scale(0.95); opacity: 0.5; }
                                  }
                                `}
                                </style>
                                {tasks.map((task) => (
                                    <tr key={task.db_id || task.id}>
                                        <td style={{fontFamily: 'monospace', color: 'var(--text-muted)'}}>{String(task.id).substring(0, 12)}...</td>
                                        <td style={{fontWeight: 500}}>{task.name.split(': ').pop()}</td>
                                        <td style={{color: 'var(--neon-cyan)', fontWeight: 'bold'}}>
                                            <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                                                <div style={{width: '8px', height: '8px', borderRadius: '50%', background: 'var(--neon-cyan)', animation: 'pulseDot 1.5s infinite'}}></div>
                                                {task.stage || 'Initializing Pipeline...'}
                                            </div>
                                        </td>
                                        <td>
                                            <span className={`${styles.processStatus} ${styles[task.status] || ''}`}>
                                                {task.status}
                                            </span>
                                        </td>
                                        <td>
                                            <button 
                                                className={styles.abortBtn}
                                                onClick={() => handleAbort(task.id)}
                                            >
                                                Abort
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </>
        )}

        {activeTab === 'Logs' && (
            <div className={`glass-panel`} style={{padding: '24px', marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px', flex: 1, maxHeight: '600px'}}>
                 <h2 className={styles.sectionTitle}>Live System Logs</h2>
                 <div 
                    ref={logsContainerRef}
                    onScroll={handleScroll}
                    className={styles.logViewerContainer} 
                    style={{flex: 1, height: '400px', overflowY: 'auto', paddingRight: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)'}}
                 >
                    {logs.length === 0 ? (
                        <p className={styles.logText}>Connected. Waiting for high-level pipeline logs...</p>
                    ) : (
                        logs.map((line, i) => renderLogLine(line, i))
                    )}
                    <div ref={logEndRef} />
                 </div>
            </div>
        )}

        {activeTab === 'Config' && (
            <div className={`glass-panel`} style={{padding: '24px', marginTop: '16px'}}>
                 <h2 className={styles.sectionTitle}>Pipeline Configuration</h2>
                 <form style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '600px' }} onSubmit={(e) => { e.preventDefault(); alert('Pipeline configuration saved!'); }}>
                     <div>
                         <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Target Repository URLs</label>
                         <textarea 
                             value={repoUrl}
                             onChange={(e) => setRepoUrl(e.target.value)}
                             style={{ width: '100%', padding: '12px', borderRadius: '12px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', color: 'white', outline: 'none', minHeight: '80px', resize: 'vertical' }}
                             placeholder="https://github.com/org/repo1.git&#10;https://github.com/org/repo2.git"
                         />
                     </div>
                     <div>
                         <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Scan Frequency</label>
                         <select style={{ width: '100%', padding: '12px', borderRadius: '12px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', color: 'white', outline: 'none' }}>
                             <option value="on-commit" style={{ background: 'var(--bg-dark)' }}>On Commit (Webhook)</option>
                             <option value="daily" style={{ background: 'var(--bg-dark)' }}>Daily</option>
                             <option value="weekly" style={{ background: 'var(--bg-dark)' }}>Weekly</option>
                         </select>
                     </div>
                     <div>
                         <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Alert Threshold (CVSS)</label>
                         <input 
                             type="number" 
                             min="0" max="10" step="0.1" defaultValue="7.0"
                             style={{ width: '100%', padding: '12px', borderRadius: '12px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', color: 'white', outline: 'none' }}
                         />
                     </div>
                     <div>
                         <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Auto-Remediation</label>
                         <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                             <input type="checkbox" id="auto-remediate" defaultChecked style={{ width: '18px', height: '18px', cursor: 'pointer' }} />
                             <label htmlFor="auto-remediate" style={{ fontSize: '0.9rem', color: 'var(--text-main)', cursor: 'pointer' }}>Generate AI Fixes via PR Comments</label>
                         </div>
                         <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                             <button 
                                 type="submit" 
                                 className="btn-primary" 
                                 style={{ flex: 1, padding: '12px', borderRadius: '12px', border: 'none', cursor: 'pointer', fontWeight: 'bold', background: 'linear-gradient(90deg, var(--neon-purple), var(--neon-cyan))', color: 'white' }}>
                                 Save Configuration
                             </button>
                             <button 
                                 type="button" 
                                 onClick={triggerManualScan}
                                 disabled={isTriggering || !repoUrl}
                                 style={{ padding: '12px 24px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.1)', cursor: (isTriggering || !repoUrl) ? 'not-allowed' : 'pointer', fontWeight: 'bold', background: 'transparent', color: (isTriggering || !repoUrl) ? 'rgba(255,255,255,0.3)' : 'var(--text-muted)' }}
                                 onMouseOver={(e) => { if(!isTriggering && repoUrl) { e.currentTarget.style.color = 'white'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.3)'; } }}
                                 onMouseOut={(e) => { if(!isTriggering && repoUrl) { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'; } }}
                             >
                                 {isTriggering ? 'Triggering...' : 'Trigger Manual Scan'}
                             </button>
                             <button 
                                 type="button" 
                                 onClick={clearScanResults}
                                 style={{ padding: '12px 16px', borderRadius: '12px', border: '1px solid rgba(239,68,68,0.4)', cursor: 'pointer', fontWeight: 'bold', background: 'rgba(239,68,68,0.08)', color: '#ef4444' }}
                                 onMouseOver={(e) => { e.currentTarget.style.background = 'rgba(239,68,68,0.18)'; e.currentTarget.style.borderColor = 'rgba(239,68,68,0.7)'; }}
                                 onMouseOut={(e) => { e.currentTarget.style.background = 'rgba(239,68,68,0.08)'; e.currentTarget.style.borderColor = 'rgba(239,68,68,0.4)'; }}
                             >
                                 🗑 Clear DB
                             </button>
                         </div>
                     </div>
                 </form>
            </div>
        )}

        {activeTab === 'Insights' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', marginTop: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '-45px' }}>
                    <button onClick={() => handleExport('csv')} className="glass-panel" style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', background: 'transparent', color: 'white', cursor: 'pointer' }}>Export CSV</button>
                    <button onClick={() => handleExport('word', 'repo_scan')} className="glass-panel" style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', background: 'transparent', color: 'var(--neon-cyan)', cursor: 'pointer', fontWeight: '500' }}>Doc: Repo Analysis</button>
                    <button onClick={() => handleExport('word', 'sca')} className="glass-panel" style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', background: 'transparent', color: 'var(--neon-cyan)', cursor: 'pointer', fontWeight: '500' }}>Doc: SCA Report</button>
                    <button onClick={() => handleExport('pdf')} className="glass-panel" style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', background: 'var(--neon-purple)', color: 'white', cursor: 'pointer', fontWeight: 'bold' }}>Export PDF</button>
                </div>
                <div className={`glass-panel`} style={{padding: '24px'}}>
                    <h2 className={styles.sectionTitle}>Pipeline History</h2>
                    <table className={styles.processList}>
                        <thead>
                            <tr>
                                <th>Scan ID</th>
                                <th>Repository</th>
                                <th>Status</th>
                                <th>Started At</th>
                                <th>Completed At</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(insights?.recent_scans || []).map((scan: any, idx: number) => (
                                <tr key={idx}>
                                    <td style={{fontFamily: 'monospace', color: 'var(--text-muted)'}}>{scan.id}</td>
                                    <td style={{fontWeight: 500}}>{scan.repo_url}</td>
                                    <td>
                                        <span className={`${styles.processStatus} ${styles[scan.status] || ''}`}>
                                            {scan.status}
                                        </span>
                                    </td>
                                    <td style={{color: 'var(--text-muted)'}}>{new Date(scan.created_at).toLocaleString()}</td>
                                    <td style={{color: 'var(--text-muted)'}}>{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '---'}</td>
                                </tr>
                            ))}
                            {(!insights?.recent_scans || insights.recent_scans.length === 0) && (
                                <tr>
                                    <td colSpan={5} style={{textAlign: 'center', padding: '24px', color: 'var(--text-muted)'}}>No scans have been run yet.</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>

                <div className={`glass-panel`} style={{padding: '24px'}}>
                    <h2 className={styles.sectionTitle}>Pipeline Analytics</h2>
                    <p style={{ color: 'var(--text-muted)', marginBottom: '24px' }}>Summary report based on your current pipeline configuration.</p>
                    
                    <div className={styles.statsGrid}>
                        <div className={`${styles.statCard}`} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className={styles.statLabel}>Total Scans Run</span>
                            <span className={`${styles.statValue}`} style={{ color: 'var(--neon-cyan)' }}>{insights?.metrics?.total_scans_run || '0'}</span>
                            <span className={`${styles.statStatus} ${styles.success}`}>Active pipelines: {tasks.filter(t => t.status.includes('Active')).length}</span>
                        </div>
                        <div className={`${styles.statCard}`} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className={styles.statLabel}>High Severity Issues</span>
                            <span className={`${styles.statValue}`} style={{ color: '#ef4444' }}>{insights?.metrics?.high || '0'}</span>
                            <span className={`${styles.statStatus} ${styles.warning}`}>Requires Attention</span>
                        </div>
                        <div className={`${styles.statCard}`} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <span className={styles.statLabel}>Auto-Remediation Rate</span>
                            <span className={`${styles.statValue}`} style={{ color: 'var(--neon-purple)' }}>{insights?.metrics?.remediation_rate || '0%'}</span>
                            <span className={`${styles.statStatus} ${styles.success}`}>Highly Effective</span>
                        </div>
                    </div>

                    <h3 className={styles.sectionTitle} style={{ fontSize: '1.05rem', margin: '24px 0 16px 0', color: 'var(--text-main)' }}>Severity Levels Breakdown</h3>
                    <div className={styles.statsGrid} style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))' }}>
                        <div className={`${styles.statCard}`} style={{ background: 'rgba(188, 19, 254, 0.05)', borderRadius: '16px', border: '1px solid rgba(188, 19, 254, 0.2)' }}>
                            <span className={styles.statLabel}>Critical</span>
                            <span className={`${styles.statValue}`} style={{ color: 'var(--neon-purple)' }}>{insights?.metrics?.critical || '0'}</span>
                        </div>
                        <div className={`${styles.statCard}`} style={{ background: 'rgba(239, 68, 68, 0.05)', borderRadius: '16px', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
                            <span className={styles.statLabel}>High</span>
                            <span className={`${styles.statValue}`} style={{ color: '#ef4444' }}>{insights?.metrics?.high || '0'}</span>
                        </div>
                        <div className={`${styles.statCard}`} style={{ background: 'rgba(245, 158, 11, 0.05)', borderRadius: '16px', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
                            <span className={styles.statLabel}>Med</span>
                            <span className={`${styles.statValue}`} style={{ color: '#f59e0b' }}>{insights?.metrics?.medium || '0'}</span>
                        </div>
                        <div className={`${styles.statCard}`} style={{ background: 'rgba(16, 185, 129, 0.05)', borderRadius: '16px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                            <span className={styles.statLabel}>Low</span>
                            <span className={`${styles.statValue}`} style={{ color: '#10b981' }}>{insights?.metrics?.low || '0'}</span>
                        </div>
                    </div>
                </div>

                <div className={`glass-panel`} style={{padding: '24px'}}>
                    <h2 className={styles.sectionTitle}>Recent Findings (Top 5)</h2>
                    <table className={styles.processList}>
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Vulnerability</th>
                                <th>Component</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(insights?.recent_findings || []).map((item: any, idx: number) => (
                                <React.Fragment key={idx}>
                                    <tr 
                                        style={{cursor: 'pointer'}} 
                                        onClick={() => setExpandedFindingIdx(expandedFindingIdx === idx ? null : idx)}
                                    >
                                        <td>
                                            <span style={{ 
                                                padding: '4px 8px', borderRadius: '8px', fontSize: '0.8rem', fontWeight: 'bold',
                                                background: item.sev === 'Critical' ? 'rgba(188, 19, 254, 0.1)' : item.sev === 'High' ? 'rgba(239, 68, 68, 0.1)' : item.sev === 'Med' ? 'rgba(245, 158, 11, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                                                color: item.sev === 'Critical' ? 'var(--neon-purple)' : item.sev === 'High' ? '#ef4444' : item.sev === 'Med' ? '#f59e0b' : '#10b981'
                                            }}>
                                                {item.sev}
                                            </span>
                                        </td>
                                        <td style={{fontWeight: 500}}>{item.vuln}</td>
                                        <td style={{fontFamily: 'monospace', color: 'var(--text-muted)'}}>{item.comp}</td>
                                        <td>
                                            <span style={{ color: item.stat.includes('Remediated') ? 'var(--neon-cyan)' : 'var(--text-muted)' }}>
                                                {item.stat} {item.patch && <span style={{fontSize: '0.8rem', opacity: 0.7, marginLeft: '8px'}}>(Click for diff)</span>}
                                            </span>
                                        </td>
                                    </tr>
                                    {expandedFindingIdx === idx && item.patch && (() => {
                                        const patchStr = String(item.patch);
                                        const isDiff = patchStr.includes('\n') || patchStr.startsWith('+') || patchStr.startsWith('-') || patchStr.startsWith('@@');
                                        return (
                                            <tr>
                                                <td colSpan={4} style={{padding: '16px', background: 'rgba(0,0,0,0.2)', borderBottom: '1px solid rgba(255,255,255,0.05)'}}>
                                                    <h4 style={{marginTop: 0, marginBottom: '8px', color: 'var(--neon-cyan)', fontSize: '0.9rem'}}>
                                                        {isDiff ? '🔧 AI Remediation Patch (Git Diff)' : '💡 Remediation Advisory'}
                                                    </h4>
                                                    {isDiff ? (
                                                        <pre style={{background: '#0d1117', padding: '12px', borderRadius: '8px', overflowX: 'auto', margin: 0, color: '#e6edf3', fontSize: '0.85rem', border: '1px solid rgba(255,255,255,0.1)'}}>
                                                            {patchStr.split('\n').map((line: string, i: number) => {
                                                                const isAdd = line.startsWith('+');
                                                                const isSub = line.startsWith('-');
                                                                return (
                                                                    <div key={i} style={{
                                                                        color: isAdd ? '#10b981' : isSub ? '#ef4444' : '#e6edf3',
                                                                        backgroundColor: isAdd ? 'rgba(16, 185, 129, 0.1)' : isSub ? 'rgba(239, 68, 68, 0.1)' : 'transparent',
                                                                        display: 'block',
                                                                        padding: '0 4px',
                                                                        margin: '0 -4px'
                                                                    }}>
                                                                        {line || '\u00A0'}
                                                                    </div>
                                                                );
                                                            })}
                                                        </pre>
                                                    ) : (
                                                        <div style={{
                                                            background: 'rgba(245, 158, 11, 0.08)',
                                                            border: '1px solid rgba(245, 158, 11, 0.3)',
                                                            borderRadius: '8px',
                                                            padding: '12px 16px',
                                                            color: '#f59e0b',
                                                            fontSize: '0.9rem',
                                                            lineHeight: '1.6'
                                                        }}>
                                                            {patchStr}
                                                        </div>
                                                    )}
                                                </td>
                                            </tr>
                                        );
                                    })()}
                                </React.Fragment>
                            ))}
                        </tbody>
                    </table>
                </div>

                <div className={`glass-panel`} style={{padding: '24px'}}>
                    <h2 className={styles.sectionTitle}>Software Bill of Materials (SBOM)</h2>
                    {insights?.sbom && insights.sbom.length > 0 ? (
                        <table className={styles.processList}>
                            <thead>
                                <tr>
                                    <th>Component Name</th>
                                    <th>Version</th>
                                    <th>Type</th>
                                    <th>Ecosystem</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(insights.sbom).map((item: any, idx: number) => (
                                    <tr key={idx}>
                                        <td style={{fontWeight: 600, color: 'var(--neon-cyan)'}}>{item.name}</td>
                                        <td style={{fontFamily: 'monospace', color: '#f59e0b'}}>{item.version}</td>
                                        <td>
                                            <span style={{ padding: '3px 8px', borderRadius: '8px', fontSize: '0.8rem', fontWeight: 'bold', background: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)' }}>
                                                {item.type}
                                            </span>
                                        </td>
                                        <td style={{color: 'var(--text-muted)', fontSize: '0.85rem'}}>
                                            {item.name.includes(':npm') || item.type === 'npm' ? '📦 npm' : '🐍 PyPI'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    ) : (
                        <div style={{textAlign: 'center', padding: '32px', color: 'var(--text-muted)'}}>
                            <div style={{fontSize: '2rem', marginBottom: '8px'}}>📦</div>
                            <p style={{margin: 0}}>No SBOM data yet. Trigger a scan on a repo with <code>package.json</code> or <code>requirements.txt</code>.</p>
                        </div>
                    )}
                </div>
            </div>
        )}

      </main>
    </div>
  );
}
