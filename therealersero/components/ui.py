import streamlit as st
from utils.analyzer import analyze_apk
from utils.llm import generate_security_report

def render_sidebar():
    with st.sidebar:
        st.title("📱 APK Analyzer")
        st.info("Upload an Android APK file to analyze its contents, permissions, and potential risks.")
        
def render_dashboard():
    st.title("APK Analysis Dashboard")
    st.write("Upload an APK to view detailed analysis, permissions, and risk scores.")
    
    # File Upload Section
    st.header("1. Upload APK")
    
    # We use a container to make it look cleaner
    upload_container = st.container(border=True)
    with upload_container:
        uploaded_file = st.file_uploader("Choose an APK file", type=["apk"], help="Maximum file size is 200MB")
    
    if uploaded_file is not None:
        st.success(f"File '{uploaded_file.name}' uploaded successfully!")
        
        st.divider()
        
        with st.spinner("Analyzing APK using androguard..."):
            analysis_result = analyze_apk(uploaded_file)
            
        if "error" in analysis_result:
            st.error(analysis_result["error"])
            return
            
        # Analysis Results Section
        st.header("2. Analysis Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("App Information")
            
            info_container = st.container(border=True)
            with info_container:
                st.write(f"**Package Name:** `{analysis_result.get('package_name', 'Unknown')}`")
                st.write(f"**Version:** `{analysis_result.get('version_name', 'Unknown')}`")
                size_mb = len(uploaded_file.getvalue()) / (1024 * 1024)
                st.write(f"**Size:** `{size_mb:.2f} MB`")
                st.write(f"**Target SDK:** `{analysis_result.get('target_sdk', 'Unknown')}`")
            
            st.subheader("Permissions")
            with st.expander(f"View Requested Permissions ({len(analysis_result.get('permissions', []))})", expanded=True):
                permissions = analysis_result.get('permissions', [])
                if not permissions:
                    st.write("No permissions found.")
                else:
                    for perm in permissions:
                        icon = "🛡️"
                        if "INTERNET" in perm or "NETWORK" in perm:
                            icon = "🌐"
                        elif "STORAGE" in perm:
                            icon = "📁"
                        elif "CAMERA" in perm:
                            icon = "📸"
                        elif "LOCATION" in perm:
                            icon = "📍"
                        st.write(f"- {icon} `{perm}`")
                
        with col2:
            st.subheader("Risk Score")
            
            risk_container = st.container(border=True)
            with risk_container:
                risk_analysis = analysis_result.get("risk_analysis", {"level": "LOW", "score": 0, "issues": []})
                level = risk_analysis["level"]
                score = risk_analysis["score"]
                
                col_score, col_delta = st.columns([1, 1])
                with col_score:
                    # Color the delta red for high risk, green for low risk
                    color = "inverse" if level == "HIGH" else "normal" if level == "LOW" else "off"
                    st.metric(label="Overall Risk", value=level, delta=f"Score: {score}", delta_color=color)
                
                with col_delta:
                    st.write(f"Risk Level: {score}/100")
                    # Provide a percentage (0 to 1) for st.progress if Streamlit version requires float, or 0-100 int.
                    st.progress(min(score, 100))
            
            st.subheader("Potential Issues")
            issues_container = st.container(border=True)
            with issues_container:
                issues = risk_analysis.get("issues", [])
                if not issues:
                    st.write("No issues to display.")
                for issue in issues:
                    if issue["type"] == "error":
                        st.error(f"🚨 {issue['message']}")
                    elif issue["type"] == "warning":
                        st.warning(f"⚠️ {issue['message']}")
                    elif issue["type"] == "info":
                        st.info(f"ℹ️ {issue['message']}")
                    else:
                        st.success(f"✅ {issue['message']}")
            
        st.divider()
        
        st.header("3. AI Security Report")
        st.info("Uses a local AI model (Ollama) to perform an in-depth analysis of the requested permissions.")
        
        if st.button("Generate AI Security Report", type="primary"):
            with st.spinner("Generating report using local Ollama model..."):
                report = generate_security_report(
                    analysis_result.get("permissions", []),
                    analysis_result.get("risk_analysis", {})
                )
                
            report_container = st.container(border=True)
            with report_container:
                st.markdown(report)

            
    else:
        st.info("Please upload an APK file to view the analysis dashboard.")
