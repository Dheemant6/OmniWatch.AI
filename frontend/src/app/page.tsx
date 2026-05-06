"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import styles from "./page.module.css";

const keywords = [
  "SBOM Generation", "Threat Intelligence", "Local AI Scanning", 
  "Zero-day Defense", "PR Auto-Remediation", "Code Context Mapping", "Supply Chain Security"
];

export default function Home() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [theme, setTheme] = useState("dark");

  const heroWords = ["Autopilot", "Auto-Remediate", "Neural Drive"];
  const [currentWordIndex, setCurrentWordIndex] = useState(0);
  const [fadeProp, setFadeProp] = useState('fade-in');

  useEffect(() => {
    const wordInterval = setInterval(() => {
      setFadeProp('fade-out');
      setTimeout(() => {
        setCurrentWordIndex((prev) => (prev + 1) % heroWords.length);
        setFadeProp('fade-in');
      }, 500); // 0.5s delay to let fade-out finish
    }, 3500); // Cycles every 3.5s
    return () => clearInterval(wordInterval);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  useEffect(() => {
    const observerOptions = {
      root: null,
      rootMargin: "0px",
      threshold: 0.15,
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
        }
      });
    }, observerOptions);

    if (containerRef.current) {
      const animatedElements = containerRef.current.querySelectorAll(".animate-on-scroll");
      animatedElements.forEach((el) => observer.observe(el));
    }

    return () => observer.disconnect();
  }, []);

  return (
    <div ref={containerRef} style={{ position: "relative", overflow: "hidden" }}>
      {/* Background Orbs */}
      <div className="glow-orb purple"></div>
      <div className="glow-orb cyan"></div>

      <div className="container">
        {/* Navbar */}
        <nav className={styles.nav}>
          <div className={styles.logo}>OMNIWATCH<span className="text-gradient">.AI</span></div>
          <div className={styles.navLinks}>
            <a href="#features" className={styles.navLink}>Platform</a>
            <a href="#pipeline" className={styles.navLink}>How it Works</a>
            <button 
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} 
              className={styles.themeToggle}
            >
              {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
            </button>
            <Link href="/dashboard" className="btn-secondary" style={{ padding: "8px 24px", fontSize: "0.95rem" }}>Login</Link>
          </div>
        </nav>

        {/* Hero Section */}
        <section className={styles.hero}>
          <style>
          {`
            .fade-in { opacity: 1; transition: opacity 0.5s ease-in, transform 0.5s ease-out; transform: translateY(0); }
            .fade-out { opacity: 0; transition: opacity 0.5s ease-out, transform 0.5s ease-in; transform: translateY(-10px); }
          `}
          </style>
          <h1 className={`${styles.title} animate-on-scroll`}>
            Shift-Left on <br />
            <span className={`text-gradient-purple ${fadeProp}`} style={{ display: 'inline-block' }}>{heroWords[currentWordIndex]}</span>
          </h1>
          <p className={`${styles.subtitle} animate-on-scroll delay-100`}>
            Don't just break the build. Fix the code. Instantly generate SBOMs, map to OSV databases, and leverage a local Qwen AI model to inherently write zero-day vulnerability patches for your GitHub Pull Requests.
          </p>
          <div className={`${styles.ctaGroup} animate-on-scroll delay-200`}>
            <Link href="/dashboard" className="btn-primary">View Dashboard</Link>
            <a href="#pipeline" className="btn-secondary">Explore Architecture</a>
          </div>
        </section>

        {/* Marquee Section */}
        <div className={styles.marqueeContainer}>
          <div className={styles.marqueeContent}>
            {[...keywords, ...keywords].map((word, i) => (
              <span key={i}>{word}</span>
            ))}
          </div>
        </div>

        {/* Integration Badges */}
        <div className="animate-on-scroll" style={{ display: 'flex', justifyContent: 'center', gap: '24px', flexWrap: 'wrap', marginTop: '20px', zIndex: 5, position: 'relative' }}>
          <span className="glass-panel" style={{ padding: '8px 16px', borderRadius: '16px', fontSize: '0.85rem', color: 'var(--neon-cyan)', border: '1px solid rgba(0, 240, 255, 0.2)' }}>🪝 GitHub Hooked</span>
          <span className="glass-panel" style={{ padding: '8px 16px', borderRadius: '16px', fontSize: '0.85rem', color: 'var(--neon-purple)', border: '1px solid rgba(188, 19, 254, 0.2)' }}>📦 CycloneDX SBOM</span>
          <span className="glass-panel" style={{ padding: '8px 16px', borderRadius: '16px', fontSize: '0.85rem', color: 'var(--neon-cyan)', border: '1px solid rgba(0, 240, 255, 0.2)' }}>🧠 Qwen 2.5 Local AI</span>
          <span className="glass-panel" style={{ padding: '8px 16px', borderRadius: '16px', fontSize: '0.85rem', color: 'var(--neon-purple)', border: '1px solid rgba(188, 19, 254, 0.2)' }}>🔍 OSV Database</span>
        </div>

        {/* Features Section */}
        <section id="features" className={styles.section}>
          <h2 className={`${styles.sectionTitle} animate-on-scroll`}>Unprecedented Threat Detection</h2>
          <div className={styles.grid}>
            {/* Feature 1 */}
            <div className={`${styles.card} glass-panel animate-on-scroll delay-100`}>
              <div className={styles.cardIcon}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
              </div>
              <h3 className={styles.cardTitle}>Supply Chain Defense</h3>
              <p className={styles.cardDesc}>Generates CycloneDX SBOMs natively and maps your dependency graph against global OSV threat intelligence databases to spot vulnerable packages.</p>
            </div>
            {/* Feature 2 */}
            <div className={`${styles.card} glass-panel animate-on-scroll delay-200`}>
              <div className={styles.cardIcon}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
              </div>
              <h3 className={styles.cardTitle}>Local AI Semantic Scanning</h3>
              <p className={styles.cardDesc}>Powered by a local, privacy-first Qwen 2.5 LLM. Our AI grasps your codebase's AST to detect zero-days and business-logic flaws securely.</p>
            </div>
            {/* Feature 3 */}
            <div className={`${styles.card} glass-panel animate-on-scroll delay-300`}>
              <div className={styles.cardIcon}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              </div>
              <h3 className={styles.cardTitle}>Automated PR Remediation</h3>
              <p className={styles.cardDesc}>Instead of just blocking builds, OmniWatch automatically generates and injects one-click secure code patches directly into your GitHub Pull Requests.</p>
            </div>
          </div>
        </section>

        {/* Pipeline Section */}
        <section id="pipeline" className={styles.section}>
          <h2 className={`${styles.sectionTitle} animate-on-scroll`}>The Frictionless SSDLC Timeline</h2>
          <div className={styles.pipelineFlow} style={{ position: 'relative' }}>
            {/* Decorative Timeline Background Line */}
            <div style={{ position: 'absolute', top: '35px', left: '10%', right: '10%', height: '4px', background: 'linear-gradient(90deg, transparent, var(--neon-purple), var(--neon-cyan), transparent)', opacity: 0.6, zIndex: 0, borderRadius: '50%' }} className="timeline-line"></div>
            
            {/* Step 1 */}
            <div className={`${styles.pipelineStep} animate-on-scroll delay-100`} style={{ zIndex: 1 }}>
              <div className={styles.stepNumber} style={{ boxShadow: '0 0 15px var(--neon-purple)', background: 'var(--bg-dark)' }}>1</div>
              <div className={`${styles.stepContent} glass-panel`} style={{ padding: "24px", flex: 1, borderTop: '2px solid var(--neon-cyan)' }}>
                <h3 className={styles.stepTitle}>Auto-Ingestion</h3>
                <p className={styles.stepDesc}>Instantly triggering on GitHub Webhooks, the AI securely clones the repo and generates a native CycloneDX SBOM.</p>
              </div>
            </div>
            {/* Step 2 */}
            <div className={`${styles.pipelineStep} animate-on-scroll delay-200`} style={{ zIndex: 1 }}>
              <div className={styles.stepNumber} style={{ boxShadow: '0 0 15px var(--neon-cyan)', background: 'var(--bg-dark)' }}>2</div>
              <div className={`${styles.stepContent} glass-panel`} style={{ padding: "24px", flex: 1, borderTop: '2px solid var(--neon-purple)' }}>
                <h3 className={styles.stepTitle}>Neural Audit</h3>
                <p className={styles.stepDesc}>Your local Qwen AI parses the code's context while concurrently mapping dependencies against OSV threat Intel.</p>
              </div>
            </div>
            {/* Step 3 */}
            <div className={`${styles.pipelineStep} animate-on-scroll delay-300`} style={{ zIndex: 1 }}>
              <div className={styles.stepNumber} style={{ boxShadow: '0 0 15px var(--neon-purple)', background: 'var(--bg-dark)' }}>3</div>
              <div className={`${styles.stepContent} glass-panel`} style={{ padding: "24px", flex: 1, borderTop: '2px solid var(--neon-cyan)' }}>
                <h3 className={styles.stepTitle}>One-Click Patch</h3>
                <p className={styles.stepDesc}>Zero build friction. The AI writes the CWE/CVE fix and comments the exact patch right into the developer's PR.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className={styles.footer}>
          <p>&copy; {new Date().getFullYear()} OmniWatch AI Security. All rights reserved.</p>
        </footer>
      </div>
    </div>
  );
}
