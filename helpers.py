from pathlib import Path
import streamlit as st

def load_css():
    css = Path("assets/style.css")
    if css.exists():
        st.markdown(f"<style>{css.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)

def hero(title, subtitle):
    st.markdown("<div class='hero'>", unsafe_allow_html=True)
    st.markdown(f"<div class='title-main'>{title}</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='title-sub'>{subtitle}</div>", unsafe_allow_html=True)
    st.markdown(
        "<span class='pill pill-a'>Login-first Web App</span>"
        "<span class='pill pill-b'>BERT SMS</span>"
        "<span class='pill pill-c'>XGBoost URL</span>"
        "<span class='pill pill-d'>Graduate Level</span>",
        unsafe_allow_html=True
    )
    st.markdown("</div>", unsafe_allow_html=True)

def card_open():
    st.markdown("<div class='card'>", unsafe_allow_html=True)

def card_close():
    st.markdown("</div>", unsafe_allow_html=True)

def metric_card(label, value, note=""):
    st.markdown(
        f"""
        <div class='kpi'>
          <div class='kpi-label'>{label}</div>
          <div class='kpi-value'>{value}</div>
          <div class='kpi-note'>{note}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

def footer():
    st.markdown("<div class='footer'>Design and Evaluation of a Hybrid ML-Based Phishing Detection System for Mobile SMS and URLs</div>", unsafe_allow_html=True)
