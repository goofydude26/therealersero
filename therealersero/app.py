import streamlit as st
from components.ui import render_dashboard, render_sidebar

# Configure the Streamlit page
st.set_page_config(
    page_title="APK Analyzer",
    page_icon="📱",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    """
    Main entry point for the Streamlit application.
    Renders the sidebar and the main dashboard.
    """
    # Render the sidebar
    render_sidebar()
    
    # Render the main dashboard content
    render_dashboard()

if __name__ == "__main__":
    main()
