"""InfraGuard — Multi-Cloud Security Guardrail Auditor Dashboard.

Streamlit frontend consuming only published FastAPI REST endpoints (PRD §11).
"""

from __future__ import annotations

import os

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.api_client import ApiClientError, InfraGuardApiClient

# Page configuration
st.set_page_config(
    page_title="InfraGuard | Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# API client initialization
API_URL = os.environ.get("INFRAGUARD_API_URL", "http://127.0.0.1:8000")


@st.cache_resource
def get_client(url: str) -> InfraGuardApiClient:
    return InfraGuardApiClient(base_url=url)


client = get_client(API_URL)

# Initialize session state
if "active_page" not in st.session_state:
    st.session_state.active_page = "New Scan"
if "current_scan_id" not in st.session_state:
    st.session_state.current_scan_id = None
if "current_scan_data" not in st.session_state:
    st.session_state.current_scan_data = None


# --- Sidebar ---
st.sidebar.title("🛡️ InfraGuard")
st.sidebar.caption("Multi-Cloud IaC Security Auditor")

# Health indicator
try:
    health = client.get_health()
    st.sidebar.success(f"● Backend Online (v{health.get('version', '1.0.0')})")
except Exception:
    st.sidebar.error("○ Backend Offline")
    st.sidebar.warning("Ensure FastAPI server is running on `http://127.0.0.1:8000`")

st.sidebar.markdown("---")

# Navigation menu
pages = ["Overview", "New Scan", "Scan Results", "Scan History", "Rule Catalogue"]
selected_page = st.sidebar.radio(
    "Navigation",
    pages,
    index=pages.index(st.session_state.active_page) if st.session_state.active_page in pages else 1,
)
st.session_state.active_page = selected_page

st.sidebar.markdown("---")
st.sidebar.info(
    "**Deterministic Scoring:**\nCritical: -25 pts\nHigh: -15 pts\nMedium: -7 pts\nLow: -3 pts"
)


# --- Helper UI Components ---
def render_risk_badge(band: str):
    colors = {
        "LOW": ("#d4edda", "#155724"),
        "MODERATE": ("#fff3cd", "#856404"),
        "HIGH": ("#f8d7da", "#721c24"),
        "CRITICAL": ("#721c24", "#ffffff"),
    }
    bg, fg = colors.get(band.upper(), ("#e2e3e5", "#383d41"))
    st.markdown(
        f'<span style="background-color: {bg}; color: {fg}; padding: 4px 12px; '
        f'border-radius: 12px; font-weight: bold; font-size: 14px;">'
        f"{band.upper()} RISK</span>",
        unsafe_allow_html=True,
    )


# ==========================================
# PAGE 1: Overview
# ==========================================
if st.session_state.active_page == "Overview":
    st.title("🛡️ InfraGuard Security Guardrails")
    st.markdown(
        "Static security auditor for multi-cloud infrastructure configurations. "
        "InfraGuard evaluates Terraform HCL and CloudFormation templates against "
        "25 enterprise security guardrails without executing code or connecting to cloud providers."
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("☁️ Multi-Cloud")
        st.write("Unified analysis across **AWS**, **Azure**, and **GCP** infrastructure.")
    with col2:
        st.subheader("🎯 Deterministic")
        st.write("Explainable mathematical risk scoring based on finding severity penalties.")
    with col3:
        st.subheader("🔒 Static & Safe")
        st.write("Zero code execution, zero credential requirements, zero external telemetry.")

    st.markdown("---")
    st.subheader("Supported Cloud Providers & Formats")

    try:
        providers_data = client.get_providers()
        p_cols = st.columns(len(providers_data))
        for idx, p in enumerate(providers_data):
            with p_cols[idx]:
                st.markdown(f"### {p['name']}")
                st.caption(f"Provider ID: `{p['id']}`")
                for fmt in p["supported_formats"]:
                    exts = ", ".join(fmt["extensions"])
                    st.write(f"- **{fmt['name']}** ({exts})")
    except Exception as exc:
        st.warning(f"Could not load provider list: {exc}")

    st.markdown("---")
    if st.button("🚀 Start New Security Scan", type="primary"):
        st.session_state.active_page = "New Scan"
        st.rerun()


# ==========================================
# PAGE 2: New Scan
# ==========================================
elif st.session_state.active_page == "New Scan":
    st.title("🚀 Submit Infrastructure Scan")
    st.markdown("Upload infrastructure configuration files for static security analysis.")

    # 1. Fetch supported providers and formats dynamically
    try:
        providers_data = client.get_providers()
    except Exception as exc:
        st.error(f"Failed to connect to backend: {exc}")
        providers_data = []

    if not providers_data:
        st.warning("No cloud providers available from backend. Ensure backend is running.")
    else:
        provider_options = {p["name"]: p for p in providers_data}
        selected_provider_name = st.selectbox("Cloud Provider", list(provider_options.keys()))
        selected_provider = provider_options[selected_provider_name]

        # 2. Filter format dropdown by selected provider
        format_options = {f["name"]: f for f in selected_provider["supported_formats"]}
        selected_format_name = st.selectbox("Configuration Format", list(format_options.keys()))
        selected_format = format_options[selected_format_name]

        allowed_exts = selected_format["extensions"]
        st.caption(f"Accepted file types for {selected_format_name}: `{', '.join(allowed_exts)}`")

        # 3. File upload
        uploaded_files = st.file_uploader(
            "Upload IaC Configuration Files",
            accept_multiple_files=True,
            help="Upload up to 20 files, max 5 MB each.",
        )

        # 4. Submission
        if st.button("🔍 Run Security Scan", type="primary", disabled=not uploaded_files):
            # Client-side extension validation check
            invalid_files = []
            file_payload = []
            for uf in uploaded_files:
                ext = "." + uf.name.rsplit(".", 1)[-1].lower() if "." in uf.name else ""
                if ext not in allowed_exts:
                    invalid_files.append((uf.name, ext))
                file_payload.append((uf.name, uf.getvalue()))

            if invalid_files:
                st.error(
                    f"Invalid file extension: {invalid_files[0][0]}. "
                    f"Only {', '.join(allowed_exts)} allowed for {selected_format_name}."
                )
            else:
                with st.spinner("Analyzing configuration against 25 security guardrails..."):
                    try:
                        scan_result = client.submit_scan(
                            provider=selected_provider["id"],
                            format_val=selected_format["id"],
                            files=file_payload,
                        )
                        st.session_state.current_scan_id = scan_result["scan_id"]
                        st.session_state.current_scan_data = scan_result
                        st.session_state.active_page = "Scan Results"
                        st.success("Scan completed successfully!")
                        st.rerun()
                    except ApiClientError as api_err:
                        st.error(f"Scan failed: {api_err.message}")
                        if api_err.details:
                            for d in api_err.details:
                                st.write(f"- {d}")
                    except Exception as err:
                        st.error(f"Unexpected error: {err}")


# ==========================================
# PAGE 3: Scan Results
# ==========================================
elif st.session_state.active_page == "Scan Results":
    st.title("📊 Security Scan Results")

    # Load scan data from session or query input
    scan_id_input = st.text_input(
        "Enter Scan ID to view",
        value=st.session_state.current_scan_id or "",
        placeholder="Paste a Scan UUID...",
    )

    if st.button("Load Scan") and scan_id_input:
        with st.spinner("Fetching scan results..."):
            try:
                st.session_state.current_scan_data = client.get_scan(scan_id_input.strip())
                st.session_state.current_scan_id = scan_id_input.strip()
            except ApiClientError as exc:
                st.error(exc.message)
                st.session_state.current_scan_data = None

    data = st.session_state.current_scan_data

    if not data:
        st.info("No scan currently loaded. Submit a scan from 'New Scan' or enter a Scan ID above.")
    else:
        summary = data.get("summary", {})
        score = summary.get("risk_score", 100)
        band = summary.get("risk_band", "LOW")

        # Top summary bar
        st.markdown("---")
        hcol1, hcol2, hcol3, hcol4 = st.columns([3, 2, 2, 2])
        with hcol1:
            st.markdown(f"**Scan ID:** `{data['scan_id']}`")
            st.caption(f"Provider: **{data['provider'].upper()}** | Format: **{data['format']}**")
        with hcol2:
            st.metric("Risk Score", f"{score}/100")
        with hcol3:
            st.write("**Risk Band:**")
            render_risk_badge(band)
        with hcol4:
            st.metric("Total Findings", len(data.get("findings", [])))

        # Resource and Finding Metrics
        mcol1, mcol2, mcol3, mcol4 = st.columns(4)
        mcol1.metric("Total Resources", summary.get("total_resources", 0))
        mcol2.metric("Evaluated", summary.get("resources_evaluated", 0))
        mcol3.metric("Unsupported", summary.get("resources_unsupported", 0))
        status_counts = summary.get("status_counts", {})
        mcol4.metric("Failures", status_counts.get("FAIL", 0))

        st.markdown("---")

        # Charts section
        sev_counts = summary.get("severity_counts", {})
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.subheader("Findings by Severity")
            sev_df = pd.DataFrame(
                [{"Severity": k, "Count": v} for k, v in sev_counts.items() if v > 0]
            )
            if not sev_df.empty:
                color_map = {
                    "CRITICAL": "#dc3545",
                    "HIGH": "#fd7e14",
                    "MEDIUM": "#ffc107",
                    "LOW": "#28a745",
                }
                fig = px.pie(
                    sev_df,
                    names="Severity",
                    values="Count",
                    color="Severity",
                    color_discrete_map=color_map,
                    hole=0.45,
                )
                fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=260)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("🎉 Zero security violations detected!")

        with chart_col2:
            st.subheader("Evaluation Status Distribution")
            status_df = pd.DataFrame(
                [{"Status": k, "Count": v} for k, v in status_counts.items() if v > 0]
            )
            if not status_df.empty:
                fig_status = px.bar(
                    status_df,
                    x="Status",
                    y="Count",
                    color="Status",
                    color_discrete_map={
                        "PASS": "#28a745",
                        "FAIL": "#dc3545",
                        "NOT_EVALUATED": "#6c757d",
                        "UNSUPPORTED": "#17a2b8",
                    },
                )
                fig_status.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=260)
                st.plotly_chart(fig_status, use_container_width=True)

        st.markdown("---")

        # Report Download Buttons
        st.subheader("Export Report")
        dcol1, dcol2, _ = st.columns([2, 2, 6])
        try:
            with dcol1:
                json_bytes, _ = client.get_report(data["scan_id"], fmt="json")
                st.download_button(
                    label="📥 Download JSON Report",
                    data=json_bytes,
                    file_name=f"infraguard-{data['scan_id']}.json",
                    mime="application/json",
                )
            with dcol2:
                csv_bytes, _ = client.get_report(data["scan_id"], fmt="csv")
                st.download_button(
                    label="📥 Download CSV Report",
                    data=csv_bytes,
                    file_name=f"infraguard-{data['scan_id']}.csv",
                    mime="text/csv",
                )
        except Exception as exc:
            st.warning(f"Could not load export buttons: {exc}")

        st.markdown("---")

        # Findings Detail Table & Cards
        st.subheader("Security Findings")
        findings = data.get("findings", [])

        if not findings:
            st.info("No findings recorded for this scan.")
        else:
            # Filters
            fcol1, fcol2 = st.columns(2)
            with fcol1:
                status_filter = st.multiselect(
                    "Filter by Status",
                    ["FAIL", "PASS", "NOT_EVALUATED", "UNSUPPORTED"],
                    default=["FAIL"],
                )
            with fcol2:
                sev_filter = st.multiselect(
                    "Filter by Severity",
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                )

            filtered_findings = [
                f
                for f in findings
                if (not status_filter or f["status"] in status_filter)
                and (not sev_filter or f["severity"] in sev_filter)
            ]

            st.write(f"Showing **{len(filtered_findings)}** of {len(findings)} findings:")

            for f in filtered_findings:
                status_icon = (
                    "❌" if f["status"] == "FAIL" else "✅" if f["status"] == "PASS" else "⚠️"
                )
                expander_title = (
                    f"{status_icon} [{f['status']}] {f['rule_id']} — "
                    f"Resource: {f['resource_id']} ({f['resource_type']})"
                )
                with st.expander(expander_title, expanded=(f["status"] == "FAIL")):
                    st.markdown(
                        f"**Severity:** `{f['severity']}` | **Source:** `{f['source_file']}`"
                    )
                    st.markdown(f"**Evidence:**\n> {f['evidence']}")
                    st.markdown(f"**Remediation:**\n{f['remediation']}")
                    if f.get("reference_urls"):
                        st.markdown("**References:**")
                        for ref in f["reference_urls"]:
                            st.markdown(f"- [{ref}]({ref})")

        # Diagnostics section (if any)
        diagnostics = data.get("diagnostics", [])
        if diagnostics:
            with st.expander(f"⚠️ Parser Diagnostics ({len(diagnostics)} items)"):
                for d in diagnostics:
                    st.warning(f"[{d['severity'].upper()}] {d['file']}: {d['message']}")


# ==========================================
# PAGE 4: Scan History
# ==========================================
elif st.session_state.active_page == "Scan History":
    st.title("📜 Scan History")
    st.markdown("View historical scan runs and navigate to past reports.")

    # Provider filter
    p_filter = st.selectbox("Filter by Provider", ["All", "aws", "azure", "gcp"])
    provider_param = None if p_filter == "All" else p_filter

    try:
        history_resp = client.get_scans(page=1, page_size=50, provider=provider_param)
        items = history_resp.get("items", [])

        if not items:
            st.info("No scan history found. Run a new scan from the 'New Scan' page.")
        else:
            table_rows = []
            for item in items:
                table_rows.append(
                    {
                        "Scan ID": item["scan_id"],
                        "Timestamp": item["created_at"][:19].replace("T", " "),
                        "Provider": item["provider"].upper(),
                        "Format": item["format"],
                        "Risk Score": item["risk_score"],
                        "Risk Band": item["risk_band"] or "N/A",
                        "Violations": item["fail_count"],
                    }
                )

            df = pd.DataFrame(table_rows)
            st.dataframe(df, use_container_width=True)

            # View details selection
            st.subheader("Inspect Historical Scan")
            scan_ids = [item["scan_id"] for item in items]
            selected_scan = st.selectbox("Select Scan ID", scan_ids)
            if st.button("Open Scan in Results View"):
                st.session_state.current_scan_id = selected_scan
                st.session_state.current_scan_data = client.get_scan(selected_scan)
                st.session_state.active_page = "Scan Results"
                st.rerun()

    except Exception as exc:
        st.error(f"Failed to load scan history: {exc}")


# ==========================================
# PAGE 5: Rule Catalogue
# ==========================================
elif st.session_state.active_page == "Rule Catalogue":
    st.title("📖 Security Rule Catalogue")
    st.markdown(
        "Complete reference for all 25 active guardrail rules enforcing "
        "security baselines across AWS, Azure, and GCP."
    )

    r_col1, r_col2 = st.columns(2)
    with r_col1:
        cat_provider = st.selectbox("Filter Provider", ["All", "aws", "azure", "gcp"])
    with r_col2:
        cat_sev = st.selectbox("Filter Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

    prov_param = None if cat_provider == "All" else cat_provider
    sev_param = None if cat_sev == "All" else cat_sev

    try:
        rules_data = client.get_rules(provider=prov_param, severity=sev_param)
        rules_list = rules_data.get("rules", [])

        st.caption(
            f"Showing **{len(rules_list)}** active rules (Baseline v{rules_data.get('policy_version', '1.0.0')}):"
        )

        for r in rules_list:
            with st.expander(
                f"[{r['severity']}] {r['rule_id']}: {r['title']} ({r['provider'].upper()})"
            ):
                st.markdown(f"**Description:** {r['description']}")
                st.markdown(f"**Applies to Resources:** `{', '.join(r['resource_types'])}`")
                st.markdown(f"**Rationale:**\n> {r['rationale']}")
                st.markdown(f"**Remediation:**\n{r['remediation']}")
                if r.get("references"):
                    st.markdown("**References:**")
                    for ref in r["references"]:
                        st.markdown(f"- [{ref}]({ref})")
    except Exception as exc:
        st.error(f"Failed to load rule catalogue: {exc}")
