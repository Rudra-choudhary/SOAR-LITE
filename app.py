import os
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from utils.input_parser import validate_ioc
from modules import virustotal, abuseipdb, shodan_module, alienvault
from modules.score_engine import calculate_weighted_score, get_recommendation
from utils.report_generator import generate_markdown_report, generate_pdf_report
from utils.notifier import send_discord_alert


# ─── Page Config ───────────────────────────────────────────────
st.set_page_config(
    page_title="SOAR-Lite | Threat Intel Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── Session State ─────────────────────────────────────────────
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "last_scan" not in st.session_state:
    st.session_state.last_scan = None

if "bulk_results" not in st.session_state:
    st.session_state.bulk_results = None

# ─── Custom CSS ────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg: #080c14;
    --text: #e8eef7;
}

* { box-sizing: border-box; }

.stApp {
    background:
        radial-gradient(circle at 15% 0%, rgba(56,217,255,.055), transparent 28%),
        radial-gradient(circle at 85% 5%, rgba(139,124,255,.05), transparent 25%),
        linear-gradient(145deg, var(--bg) 0%, #0a101a 48%, #0b111b 100%);
    color: var(--text);
    font-family: Inter, sans-serif;
}

.block-container {
    max-width: 1380px;
    padding: 2.2rem 2.5rem 3rem;
}

#MainMenu, footer, .stDeployButton { display:none; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#090e17 0%,#0b111b 100%) !important;
    border-right: 1px solid #1b2737;
}
section[data-testid="stSidebar"] hr { border-color: #1c2838; margin: 1rem 0; }
section[data-testid="stSidebar"] h3 { color:#718197; font-size:.68rem; letter-spacing:1.2px; text-transform:uppercase; font-family:"JetBrains Mono",monospace; margin-top:1.15rem; }

/* Header */
.main-title {
    font-size: 3rem; line-height:1; font-weight:800; letter-spacing:-1.8px; text-align:left;
    background:linear-gradient(100deg,#f5f9ff 10%,#65ddff 50%,#9a8cff 92%);
    -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin: .2rem 0 .55rem;
}
.subtitle { color:#8b9aae; font-size:.9rem; letter-spacing:.1px; text-align:left; margin-bottom:.2rem; }
.creator { color:#536276; font:600 .66rem "JetBrains Mono",monospace; letter-spacing:1.2px; text-align:left; text-transform:uppercase; margin-bottom:1.45rem; }

/* Search / Inputs */
.stTextInput > div > div > input {
    background:#0a111b !important; color:#edf5ff !important; border:1px solid #263449 !important;
    border-radius:10px !important; font:500 .88rem "JetBrains Mono",monospace !important; min-height:46px !important; padding-left:14px !important;
}
.stTextInput > div > div > input:focus { border-color:#38d9ff !important; box-shadow:0 0 0 1px rgba(56,217,255,.18),0 0 25px rgba(56,217,255,.05) !important; }

/* Buttons */
.stButton > button, .stDownloadButton > button {
    min-height:44px !important; border-radius:9px !important; font-weight:600 !important;
    border:1px solid #2a3a50 !important; background:#141e2c !important; color:#dbe7f5 !important; transition:.18s ease !important;
}
.stButton > button:hover, .stDownloadButton > button:hover { border-color:#3e5875 !important; transform:translateY(-1px); }
.stButton > button[kind="primary"] {
    background:linear-gradient(135deg,#39d99b,#27c88d) !important; color:#041a12 !important; border:0 !important; box-shadow:0 8px 22px rgba(53,211,154,.13);
}

/* Metrics */
div[data-testid="stMetric"] {
    background:linear-gradient(145deg,#121b29,#0e151f); border:1px solid #233147; border-radius:12px; padding:15px 17px; box-shadow:0 8px 25px rgba(0,0,0,.15); min-height:105px;
}
div[data-testid="stMetric"] label { color:#6f7f94 !important; text-transform:uppercase; letter-spacing:1px; font:600 .64rem "JetBrains Mono",monospace !important; }
div[data-testid="stMetricValue"] { color:#f4f8fc !important; font-weight:750 !important; letter-spacing:-.5px; }

/* Severity */
.severity-wrap { text-align:left; margin:1rem 0 .55rem; }
.severity-badge { display:inline-flex; align-items:center; gap:7px; padding:7px 13px; border-radius:7px; font:700 .69rem "JetBrains Mono",monospace; letter-spacing:1px; border:1px solid; }
.sev-critical {background:rgba(240,91,112,.10);color:#ff8799;border-color:rgba(240,91,112,.35);}
.sev-high {background:rgba(251,123,69,.10);color:#ff9b73;border-color:rgba(251,123,69,.32);}
.sev-medium {background:rgba(245,189,63,.10);color:#ffd56c;border-color:rgba(245,189,63,.30);}
.sev-low {background:rgba(53,211,154,.09);color:#63e5b6;border-color:rgba(53,211,154,.28);}
.sev-clean {background:rgba(53,211,154,.09);color:#63e5b6;border-color:rgba(53,211,154,.28);}
.sev-unknown {background:rgba(100,116,139,.10);color:#aab6c6;border-color:#334155;}

/* Expanders / DataFrames */
div[data-testid="stExpander"] { background:#0e1621; border:1px solid #202e40; border-radius:10px; margin:.4rem 0; }
div[data-testid="stExpander"] summary { color:#dbe5f0 !important; font-weight:600; }
div[data-testid="stDataFrame"] { border:1px solid #202e40; border-radius:9px; overflow:hidden; }

/* Footer */
.footer-note { text-align:center; color:#4d5d72; font:600 .62rem "JetBrains Mono",monospace; letter-spacing:.5px; margin-top:2.3rem; padding-top:1rem; border-top:1px solid #1b2737; }
</style>
""", unsafe_allow_html=True)


# ─── HELPER FUNCTIONS ──────────────────────────────────────────

def run_scan(ioc_input: str, show_ui: bool = True):
    """Run all intelligence modules. Supports silent mode for bulk scans."""
    ioc_info = validate_ioc(ioc_input)
    if not ioc_info["valid"]:
        return None

    ioc_type = ioc_info["type"]
    results = []

    sources = [
        ("VirusTotal", virustotal, "🦠"),
        ("AbuseIPDB", abuseipdb, "🚫"),
        ("Shodan", shodan_module, "🔎"),
        ("AlienVault OTX", alienvault, "👽"),
    ]

    progress_bar = None
    status_box = None

    if show_ui:
        progress_bar = st.progress(0, text="Initializing threat scan...")
        status_box = st.empty()

    for i, (name, module, icon) in enumerate(sources):
        if show_ui:
            status_box.info(f"{icon} Querying **{name}**...")
        
        result = module.query(ioc_input, ioc_type)
        results.append(result)
        
        if show_ui:
            progress_bar.progress((i + 1) / len(sources), text=f"Completed {name}")
        time.sleep(0.3)

    if show_ui:
        status_box.success("All intelligence sources queried successfully.")
        time.sleep(0.6)
        status_box.empty()
        progress_bar.empty()

    score_data = calculate_weighted_score(results)

    return {
        "ioc": ioc_input,
        "ioc_type": ioc_type,
        "results": results,
        "score_data": score_data,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

def parse_uploaded_iocs(uploaded_file):
    """Parse uploaded TXT or CSV file and return a clean IOC list."""
    filename = uploaded_file.name.lower()
    
    if filename.endswith(".txt"):
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        iocs = [line.strip() for line in content.splitlines() if line.strip()]
        return list(dict.fromkeys(iocs))  # Remove duplicates
        
    elif filename.endswith(".csv"):
        df = pd.read_csv(uploaded_file)
        possible_cols = ["ioc", "indicator", "value", "ip", "domain"]
        found_col = next((col for col in df.columns if col.strip().lower() in possible_cols), df.columns[0])
        iocs = df[found_col].dropna().astype(str).str.strip().tolist()
        return list(dict.fromkeys([ioc for ioc in iocs if ioc]))
        
    return []

def run_bulk_scan(ioc_list):
    """Run scans for multiple IOCs quietly and return a summary dataframe."""
    bulk_results = []
    progress = st.progress(0, text="Starting bulk IOC scan...")
    status = st.empty()
    total = len(ioc_list)

    for idx, ioc in enumerate(ioc_list, start=1):
        status.info(f"Scanning {idx}/{total}: {ioc}")
        scan_result = run_scan(ioc, show_ui=False)

        if scan_result is None:
            bulk_results.append({
                "IOC": ioc, "Type": "Unknown", "Score": 0, "Severity": "INVALID",
                "Timestamp": datetime.utcnow().strftime("%H:%M:%S UTC")
            })
        else:
            bulk_results.append({
                "IOC": scan_result["ioc"],
                "Type": scan_result["ioc_type"].upper(),
                "Score": scan_result["score_data"]["final_score"],
                "Severity": scan_result["score_data"]["severity"],
                "Timestamp": scan_result["timestamp"]
            })
            
            # Save to sidebar history
            st.session_state.scan_history.append({
                "ioc": scan_result["ioc"],
                "score": scan_result["score_data"]["final_score"],
                "severity": scan_result["score_data"]["severity"],
            })

        progress.progress(idx / total, text=f"Completed {idx}/{total}")

    status.success("Bulk scan completed successfully!")
    time.sleep(1)
    status.empty()
    progress.empty()
    
    return pd.DataFrame(bulk_results)

def render_dashboard(scan_result: dict):
    """Render the detailed dashboard for a single scan."""
    ioc = scan_result["ioc"]
    ioc_type = scan_result["ioc_type"]
    results = scan_result["results"]
    score_data = scan_result["score_data"]
    severity = score_data["severity"]
    score = score_data["final_score"]

    sev_class = f"sev-{severity.lower()}" if severity.lower() in ["critical", "high", "medium", "low", "clean"] else "sev-unknown"
    successful_sources = sum(1 for r in results if not r.get("error") and not r.get("skipped"))

    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Threat Score", f"{score}/100")
    m2.metric("Severity", severity)
    m3.metric("IOC Type", ioc_type.upper())
    m4.metric("Active Sources", f"{successful_sources}/{len(results)}")

    st.markdown(f'<div class="severity-wrap"><span class="severity-badge {sev_class}">{severity} RISK DETECTED</span></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="recommendation-box"><strong>Analyst Recommendation</strong><br><br>{get_recommendation(severity)}</div>', unsafe_allow_html=True)

    st.markdown("### Detailed Findings")
    for result in results:
        source_name = result.get("source", "Unknown")
        source_score = result.get("score", "N/A")
        
        if result.get("error"): exp_label = f"⚠️ {source_name} (Error)"
        elif result.get("skipped"): exp_label = f"⏭️ {source_name} (Skipped)"
        else: exp_label = f"✅ {source_name} — Score: {source_score}/100"

        with st.expander(exp_label, expanded=False):
            if result.get("error"): st.warning(result["error"])
            elif result.get("skipped"): st.info("Source does not support this IOC type.")
            else:
                cleaned = {k.replace("_", " ").title(): str(v) for k, v in result.items() if k not in ["source", "error", "skipped"]}
                st.dataframe(pd.DataFrame(cleaned.items(), columns=["Field", "Value"]), use_container_width=True, hide_index=True)


# ─── SIDEBAR ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;">
        <div style="width:34px;height:34px;border:1px solid #2c4158;border-radius:9px;
                    display:flex;align-items:center;justify-content:center;
                    background:#0e1a27;color:#38d9ff;font-size:18px;">◈</div>
        <div>
            <div style="font-weight:750;color:#f4f8fc;font-size:15px;">SOAR-Lite</div>
            <div style="font-size:9px;color:#607086;font-family:JetBrains Mono,monospace;
                        letter-spacing:.7px;">THREAT INTELLIGENCE</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### Active Sources")
    for source in ["VirusTotal", "AbuseIPDB", "Shodan", "AlienVault OTX"]:
        st.markdown(f'<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 2px;color:#b6c3d2;font-size:12px;"><span>{source}</span><span style="color:#35d39a;font:9px JetBrains Mono,monospace;">● ONLINE</span></div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### Scan History")
    if st.session_state.scan_history:
        sev_colors = {"CRITICAL":"#f05b70","HIGH":"#fb7b45","MEDIUM":"#f5bd3f","LOW":"#35d39a","CLEAN":"#35d39a","UNKNOWN":"#7b8aa0"}
        for entry in reversed(st.session_state.scan_history[-8:]):
            c = sev_colors.get(entry["severity"], "#7b8aa0")
            st.markdown(
                f'<div style="padding:8px 7px;margin:4px 0;background:#0d151f;border:1px solid #1d2a3a;border-radius:7px;">'
                f'<div style="display:flex;justify-content:space-between;gap:5px;">'
                f'<span style="font:10px JetBrains Mono,monospace;color:#9aa8ba;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{entry["ioc"]}</span>'
                f'<strong style="font:11px JetBrains Mono,monospace;color:{c};">{entry["score"]}</strong>'
                f'</div><div style="margin-top:3px;font:9px JetBrains Mono,monospace;color:{c};">{entry["severity"]}</div>'
                f'</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="color:#536277;font-size:11px;">No scans yet.</div>', unsafe_allow_html=True)


# ─── MAIN UI ───────────────────────────────────────────────────
st.markdown('<div class="main-title">SOAR-Lite</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Automated Multi-Source Threat Intelligence & Triage Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="creator">SOC ANALYST CONSOLE &nbsp;•&nbsp; MULTI-SOURCE IOC TRIAGE</div>', unsafe_allow_html=True)

# ─── TABS FOR SINGLE VS BULK SCAN ───
tab1, tab2 = st.tabs(["🔍 Single IOC Scan", "📂 Bulk CSV/TXT Scan"])

with tab1:
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2 = st.columns([4, 1])
    with col1:
        ioc_input = st.text_input("IOC Input", placeholder="Enter IP, Domain, URL, or File Hash...", label_visibility="collapsed")
    with col2:
        scan_clicked = st.button("Analyze IOC", type="primary", use_container_width=True)

    if scan_clicked:
        if not ioc_input:
            st.error("Please enter an IOC to analyze.")
        else:
            scan_result = run_scan(ioc_input)
            if scan_result is None:
                st.error(f"Could not identify IOC type for: `{ioc_input}`")
            else:
                st.session_state.last_scan = scan_result
                st.session_state.scan_history.append({
                    "ioc": scan_result["ioc"], "score": scan_result["score_data"]["final_score"], "severity": scan_result["score_data"]["severity"]
                })

    if st.session_state.last_scan:
        render_dashboard(st.session_state.last_scan)


with tab2:
    st.markdown("<br>", unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Upload a .TXT or .CSV file containing multiple IOCs", type=["txt", "csv"])
    
    if uploaded_file is not None:
        parsed_iocs = parse_uploaded_iocs(uploaded_file)
        
        if parsed_iocs:
            st.info(f"Successfully extracted **{len(parsed_iocs)}** unique IOCs from the file.")
            
            if st.button("🚀 Start Bulk Triage Scan", type="primary"):
                st.session_state.bulk_results = run_bulk_scan(parsed_iocs)
        else:
            st.warning("No valid IOCs were found in the uploaded file.")

    if st.session_state.bulk_results is not None:
        st.markdown("### 📊 Bulk Triage Results")
        st.dataframe(st.session_state.bulk_results, use_container_width=True, hide_index=True)
        
        csv_data = st.session_state.bulk_results.to_csv(index=False).encode("utf-8")
        st.download_button(
            "📥 Download Full Report (CSV)", 
            data=csv_data, 
            file_name=f"soar_bulk_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv", 
            mime="text/csv"
        )

# Footer
st.markdown('<div class="footer-note">SOAR-Lite v1.0 • Created by <strong>RUDRA CHOUDHARY</strong></div>', unsafe_allow_html=True)
