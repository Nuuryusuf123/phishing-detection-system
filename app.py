import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time

from utils.helpers import load_css, card_open, card_close, metric_card, footer
from utils.db import (
    init_db,
    authenticate,
    save_history,
    load_history,
    create_user,
    change_password,
    user_exists,
    verify_user_email,
    get_all_users,
    load_activity_logs,
    log_activity,
)
from utils.sms_bert import bert_available, predict_sms_bert
from utils.url_xgb import xgb_available, predict_url
from utils.reporting import build_pdf
from utils.feature_extractor import extract_features

st.set_page_config(
    page_title="Hybrid ML-Based Phishing Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

load_css()
init_db()

for key, default in {
    "logged_in": False,
    "role": None,
    "username": None,
    "pending_verify_user": None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


def pill(label):
    if label == "Threat Detected":
        return "<span class='pill pill-d'>Threat Detected</span>"
    elif label == "Safe":
        return "<span class='pill pill-c'>Safe</span>"
    return "<span class='pill pill-a'>No Result</span>"


def gauge(score, title, color="#22C1FF"):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score * 100,
        number={"suffix": "%"},
        title={"text": title},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 49], "color": "#123A2D"},
                {"range": [49, 70], "color": "#3B2B12"},
                {"range": [70, 100], "color": "#4A1212"},
            ]
        }
    ))
    fig.update_layout(
        height=300,
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=8, r=8, t=35, b=8)
    )
    return fig


def ai_scan(message: str):
    with st.spinner(message):
        progress = st.progress(0)
        for i in range(100):
            time.sleep(0.01)
            progress.progress(i + 1)
        progress.empty()


def play_alert_sound(sound_type="danger"):
    if sound_type == "danger":
        st.markdown(
            """
            <audio autoplay>
                <source src="https://actions.google.com/sounds/v1/alarms/beep_short.ogg" type="audio/ogg">
            </audio>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <audio autoplay>
                <source src="https://actions.google.com/sounds/v1/cartoon/wood_plank_flicks.ogg" type="audio/ogg">
            </audio>
            """,
            unsafe_allow_html=True,
        )


def require_admin():
    if st.session_state.role != "admin":
        st.warning("Only admin can access this section.")
        st.stop()


def require_analyst_or_admin():
    if st.session_state.role not in ["admin", "analyst"]:
        st.warning("Only analyst or admin can access this section.")
        st.stop()


# ---------------- SIMPLE TOP TITLE ----------------
st.markdown("""
<div class="hero">
    <div class="title-main">🛡️ Hybrid ML-Based Phishing Detection System</div>
</div>
""", unsafe_allow_html=True)

# ---------------- LOGIN PAGE ----------------
if not st.session_state.logged_in:
    left, center, right = st.columns([0.8, 1.2, 0.8], gap="large")

    with left:
        st.markdown(
            "<h1 style='margin-top:140px; color:white; font-size:64px; font-weight:900;'>WELCOME</h1>",
            unsafe_allow_html=True
        )

    with center:
        # card_open()
        st.subheader("🔐 Login / Register")

        tab1, tab2, tab3, tab4 = st.tabs(["Login", "Sign Up", "Forgot Password", "Verify Email"])

        # -------- LOGIN --------
        with tab1:
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")

            if st.button("Login", use_container_width=True, key="login_btn"):
                ok, role = authenticate(username, password)
                if ok:
                    st.session_state.logged_in = True
                    st.session_state.role = role
                    st.session_state.username = username
                    st.success("Login successful.")
                    log_activity(username, "LOGIN", f"User logged in with role={role}")
                    play_alert_sound("safe")
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
                    play_alert_sound("danger")

        # -------- SIGN UP --------
        with tab2:
            new_user = st.text_input("New Username", key="signup_username")
            new_email = st.text_input("Email", key="signup_email")
            new_pass = st.text_input("New Password", type="password", key="signup_password")
            new_role = st.selectbox("Role", ["user", "analyst", "admin"], index=0, key="signup_role")

            if st.button("Create Account", use_container_width=True, key="signup_btn"):
                if not new_user.strip() or not new_pass.strip() or not new_email.strip():
                    st.warning("Please fill all fields.")
                    play_alert_sound("danger")
                elif user_exists(new_user):
                    st.warning("User already exists.")
                    play_alert_sound("danger")
                else:
                    ok, msg = create_user(new_user, new_pass, new_role, new_email)
                    if ok:
                        st.session_state.pending_verify_user = new_user
                        st.success("Account created successfully. Please verify the email manually in the next tab.")
                        log_activity(new_user, "SIGNUP", f"New account created with role={new_role}")
                        play_alert_sound("safe")
                    else:
                        st.error(msg)
                        play_alert_sound("danger")

        # -------- FORGOT PASSWORD --------
        with tab3:
            reset_user = st.text_input("Enter Username", key="reset_username")
            reset_pass = st.text_input("New Password", type="password", key="reset_password")

            if st.button("Reset Password", use_container_width=True, key="reset_btn"):
                if not reset_user.strip() or not reset_pass.strip():
                    st.warning("Please fill all fields.")
                    play_alert_sound("danger")
                elif user_exists(reset_user):
                    ok, msg = change_password(reset_user, reset_pass)
                    if ok:
                        st.success(msg)
                        log_activity(reset_user, "RESET_PASSWORD", "Password reset from forgot-password form")
                        play_alert_sound("safe")
                    else:
                        st.error(msg)
                        play_alert_sound("danger")
                else:
                    st.error("User not found.")
                    play_alert_sound("danger")

        # -------- VERIFY EMAIL --------
        with tab4:
            verify_user = st.text_input(
                "Username to verify",
                value=st.session_state.pending_verify_user if st.session_state.pending_verify_user else "",
                key="verify_user_input"
            )
            st.caption("Basic verification mode. SMTP/OTP can be added later.")
            if st.button("Verify User Email", use_container_width=True, key="verify_btn"):
                if not verify_user.strip():
                    st.warning("Enter a username first.")
                    play_alert_sound("danger")
                elif not user_exists(verify_user):
                    st.error("User not found.")
                    play_alert_sound("danger")
                else:
                    verify_user_email(verify_user)
                    st.success("User email marked as verified.")
                    play_alert_sound("safe")

        card_close()

    with right:
        st.empty()

    footer()
    st.stop()

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.image("assets/logo.svg", width=108)
    st.markdown(f"### {st.session_state.username}")
    st.caption(f"Role: {st.session_state.role}")

    page = st.radio(
        "Navigation",
        [
            "System Overview",
            "Dashboard",
            "SMS Detection",
            "URL Detection",
            "Hybrid Detection",
            "Detection History",
            "Download Report",
            "Admin Dashboard",
        ]
    )

    if st.button("Logout", use_container_width=True):
        log_activity(st.session_state.username, "LOGOUT", "User logged out")
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = None
        st.rerun()

    st.markdown("---")
    st.subheader("⚙️ Account Settings")
    sidebar_new_pass = st.text_input("Change Password", type="password", key="sidebar_change_password")

    if st.button("Update Password", use_container_width=True, key="sidebar_update_password"):
        if not sidebar_new_pass.strip():
            st.warning("Please enter a new password.")
            play_alert_sound("danger")
        else:
            ok, msg = change_password(st.session_state.username, sidebar_new_pass)
            if ok:
                st.success(msg)
                play_alert_sound("safe")
            else:
                st.error(msg)
                play_alert_sound("danger")

history = load_history()

# ---------------- PAGES ----------------
if page == "System Overview":
    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("SMS Dataset", "10,000", "Ready for BERT training/testing")
    with c2:
        metric_card("URL Dataset", "10,000", "Ready for XGBoost training/testing")
    # with c3:
    #     metric_card("Deployment", "Streamlit", "Professional login-first web app")

    card_open()
    st.subheader("📘 Training and Testing Workflow")
    st.write("Train and test both models locally in VS Code inside the `scripts/` folder.")
    st.code(
        "python scripts/train_bert_sms.py\n"
        "python scripts/train_xgboost_url.py\n"
        "python scripts/evaluate_models.py"
    )
    st.write("After training, the web app loads the saved models from `models/bert_sms_model/` and `models/url/`.")
    card_close()

    card_open()
    st.subheader("🧩 Roles Overview")
    st.markdown(
        "- **admin** → full control over users, logs, analytics, and reports\n"
        "- **analyst** → can view analytics, reports, and detection history\n"
        "- **user** → can use detection modules and reports"
    )
    card_close()

elif page == "Dashboard":
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Total Scans", str(len(history)), "All recorded scans")
    with c2:
        metric_card("SMS Scans", str(len(history[history["input_type"] == "SMS"]) if len(history) else 0), "BERT activity")
    with c3:
        metric_card("URL Scans", str(len(history[history["input_type"] == "URL"]) if len(history) else 0), "XGBoost activity")
    with c4:
        metric_card("Threats", str(len(history[history["prediction"] == "Threat Detected"]) if len(history) else 0), "Flagged malicious content")

    if len(history) > 0:
        a, b = st.columns(2)

        with a:
            x = history["input_type"].value_counts().reset_index()
            fig = px.bar(x, x="input_type", y="count", title="Scans by Module")
            fig.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

        with b:
            y = history["prediction"].value_counts().reset_index()
            fig2 = px.pie(y, names="prediction", values="count", title="Prediction Distribution")
            fig2.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig2, use_container_width=True)

elif page == "SMS Detection":
    card_open()
    st.subheader("📩 BERT SMS Detection")
    sms_text = st.text_area("Paste suspicious SMS", height=220)
    run = st.button("Run SMS Detection", use_container_width=True)
    card_close()

    if run:
        if not bert_available():
            st.error("BERT model not found yet. Run: python scripts/train_bert_sms.py")
            play_alert_sound("danger")
        elif not sms_text.strip():
            st.warning("Please enter an SMS message.")
            play_alert_sound("danger")
        else:
            ai_scan("🤖 AI is scanning the SMS message...")
            label, score = predict_sms_bert(sms_text)
            save_history("SMS", sms_text, label, score)
            log_activity(st.session_state.username, "SMS_SCAN", f"Prediction={label}")

            if label == "Threat Detected":
                play_alert_sound("danger")
            else:
                play_alert_sound("safe")

            a, b = st.columns(2)
            with a:
                card_open()
                st.subheader("Prediction")
                st.markdown(pill(label), unsafe_allow_html=True)
                st.write(f"Confidence: {score:.2%}")
                card_close()

            with b:
                card_open()
                st.plotly_chart(gauge(score, "SMS Threat Confidence"), use_container_width=True)
                card_close()

elif page == "URL Detection":
    st.subheader("🌐 URL Detection")

    card_open()
    st.subheader("Automatic URL Detection (PRO)")
    direct_url = st.text_input("Enter URL directly", placeholder="https://example.com/login")
    auto_run = st.button("Analyze URL Automatically", use_container_width=True)
    card_close()

    if auto_run:
        if not xgb_available():
            st.error("XGBoost URL model not found yet. Run: python scripts/train_xgboost_url.py")
            play_alert_sound("danger")
        elif not direct_url.strip():
            st.warning("Please enter a URL.")
            play_alert_sound("danger")
        else:
            ai_scan("🛡️ Extracting URL features and running XGBoost analysis...")
            features = extract_features(direct_url)
            label, score, explain = predict_url(features)
            save_history("URL", direct_url, label, score)
            log_activity(st.session_state.username, "URL_SCAN_AUTO", f"Prediction={label}")

            if label == "Threat Detected":
                play_alert_sound("danger")
            else:
                play_alert_sound("safe")

            a, b = st.columns(2)
            with a:
                card_open()
                st.subheader("Prediction")
                st.markdown(pill(label), unsafe_allow_html=True)
                st.write(f"Confidence: {score:.2%}")
                card_close()

            with b:
                card_open()
                st.plotly_chart(gauge(score, "Automatic URL Threat Confidence", "#3B82F6"), use_container_width=True)
                card_close()

            card_open()
            st.subheader("Extracted Features")
            st.dataframe(pd.DataFrame([features]), use_container_width=True)
            card_close()

            if explain:
                card_open()
                st.subheader("Explainability")
                df = pd.DataFrame(explain)
                fig = px.bar(df, x="feature", y="importance", color="value", title="Top URL Feature Importance")
                fig.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(df, use_container_width=True)
                card_close()

    st.markdown("---")

    card_open()
    st.subheader("Manual Feature Input")
    c1, c2, c3 = st.columns(3)

    with c1:
        url_length = st.number_input("URL length", min_value=0, value=85)
        host_length = st.number_input("Host length", min_value=0, value=26)
        path_length = st.number_input("Path length", min_value=0, value=34)
        num_dots = st.number_input("Number of dots", min_value=0, value=4)

    with c2:
        num_hyphens = st.number_input("Number of hyphens", min_value=0, value=2)
        num_at = st.number_input("Number of @ symbols", min_value=0, value=0)
        num_digits = st.number_input("Number of digits", min_value=0, value=6)
        has_https = st.selectbox("Uses HTTPS", [1, 0], index=0)

    with c3:
        entropy = st.number_input("Entropy", min_value=0.0, value=4.6, step=0.1)
        has_login_word = st.selectbox("Contains 'login'", [1, 0], index=1)
        has_verify_word = st.selectbox("Contains 'verify'", [1, 0], index=1)

    run = st.button("Run Manual URL Detection", use_container_width=True)
    card_close()

    if run:
        if not xgb_available():
            st.error("XGBoost URL model not found yet. Run: python scripts/train_xgboost_url.py")
            play_alert_sound("danger")
        else:
            ai_scan("🛡️ Running manual URL feature analysis...")
            features = {
                "url_length": url_length,
                "host_length": host_length,
                "path_length": path_length,
                "num_dots": num_dots,
                "num_hyphens": num_hyphens,
                "num_at": num_at,
                "num_digits": num_digits,
                "has_https": has_https,
                "entropy": entropy,
                "has_login_word": has_login_word,
                "has_verify_word": has_verify_word
            }

            label, score, explain = predict_url(features)
            save_history("URL", str(features), label, score)
            log_activity(st.session_state.username, "URL_SCAN_MANUAL", f"Prediction={label}")

            if label == "Threat Detected":
                play_alert_sound("danger")
            else:
                play_alert_sound("safe")

            a, b = st.columns(2)
            with a:
                card_open()
                st.subheader("Prediction")
                st.markdown(pill(label), unsafe_allow_html=True)
                st.write(f"Confidence: {score:.2%}")
                card_close()

            with b:
                card_open()
                st.plotly_chart(gauge(score, "Manual URL Threat Confidence", "#3B82F6"), use_container_width=True)
                card_close()

elif page == "Hybrid Detection":
    card_open()
    st.subheader("🧠 Hybrid Detection")
    sms_text = st.text_area("SMS message (optional)", height=140)
    direct_url = st.text_input("Enter URL directly (optional)", placeholder="https://example.com/login")
    run = st.button("Run Hybrid Detection", use_container_width=True)
    card_close()

    if run:
        if not xgb_available():
            st.error("Train URL model first: python scripts/train_xgboost_url.py")
            play_alert_sound("danger")
        else:
            sms_score, sms_label = None, "No Result"

            if sms_text.strip():
                if not bert_available():
                    st.error("Train BERT first: python scripts/train_bert_sms.py")
                    play_alert_sound("danger")
                    st.stop()
                ai_scan("⚡ Running hybrid AI detection...")
                sms_label, sms_score = predict_sms_bert(sms_text)
            else:
                ai_scan("⚡ Running hybrid AI detection...")

            if direct_url.strip():
                url_features = extract_features(direct_url)
            else:
                st.warning("Please enter a URL for hybrid detection.")
                play_alert_sound("danger")
                st.stop()

            url_label, url_score, _ = predict_url(url_features)

            scores = [x for x in [sms_score, url_score] if x is not None]
            final_score = sum(scores) / len(scores)
            final_label = "Threat Detected" if final_score >= 0.5 else "Safe"
            save_history("HYBRID", f"SMS={sms_text[:80]} | URL={direct_url}", final_label, final_score)
            log_activity(st.session_state.username, "HYBRID_SCAN", f"Prediction={final_label}")

            if final_label == "Threat Detected":
                play_alert_sound("danger")
            else:
                play_alert_sound("safe")

            a, b, c = st.columns(3)
            with a:
                card_open()
                st.subheader("SMS")
                st.markdown(pill(sms_label), unsafe_allow_html=True)
                st.write(f"Score: {sms_score:.2%}" if sms_score is not None else "No SMS")
                card_close()

            with b:
                card_open()
                st.subheader("URL")
                st.markdown(pill(url_label), unsafe_allow_html=True)
                st.write(f"Score: {url_score:.2%}")
                card_close()

            with c:
                card_open()
                st.subheader("Hybrid")
                st.markdown(pill(final_label), unsafe_allow_html=True)
                st.write(f"Final: {final_score:.2%}")
                card_close()

            chart_df = pd.DataFrame({
                "module": ["SMS", "URL", "Hybrid"],
                "score": [
                    0 if sms_score is None else sms_score * 100,
                    url_score * 100,
                    final_score * 100
                ]
            })
            fig = px.bar(chart_df, x="module", y="score", title="Hybrid Confidence Comparison")
            fig.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

elif page == "Detection History":
    require_analyst_or_admin()
    card_open()
    st.subheader("📜 Detection History")
    if len(history) > 0:
        st.dataframe(history, use_container_width=True, height=520)
    else:
        st.info("No history yet.")
    card_close()

elif page == "Download Report":
    require_analyst_or_admin()
    card_open()
    st.subheader("⬇️ Download Reports")
    if len(history) > 0:
        csv = history.to_csv(index=False).encode("utf-8")
        if st.download_button(
            "Download CSV Report",
            data=csv,
            file_name="phishing_detection_report.csv",
            mime="text/csv",
            use_container_width=True
        ):
            log_activity(st.session_state.username, "DOWNLOAD_CSV_REPORT", "CSV report downloaded")

        pdf_path = build_pdf(history.head(150), "reports/phishing_detection_report.pdf")
        with open(pdf_path, "rb") as f:
            if st.download_button(
                "Download PDF Report",
                data=f.read(),
                file_name="phishing_detection_report.pdf",
                mime="application/pdf",
                use_container_width=True
            ):
                log_activity(st.session_state.username, "DOWNLOAD_PDF_REPORT", "PDF report downloaded")
    else:
        st.info("No report available yet.")
    card_close()

elif page == "Admin Dashboard":
    require_admin()

    tabs = st.tabs(["Overview", "Users", "Activity Logs"])

    with tabs[0]:
        if len(history) > 0:
            a, b = st.columns(2)

            with a:
                d1 = history["prediction"].value_counts().reset_index()
                fig1 = px.pie(d1, names="prediction", values="count", title="Prediction Distribution")
                fig1.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig1, use_container_width=True)

            with b:
                d2 = history["input_type"].value_counts().reset_index()
                fig2 = px.bar(d2, x="input_type", y="count", title="Activity by Module")
                fig2.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig2, use_container_width=True)

            card_open()
            st.subheader("Recent Activity")
            st.dataframe(history.head(30), use_container_width=True, height=420)
            card_close()
        else:
            st.info("No analytics yet.")

    with tabs[1]:
        card_open()
        st.subheader("👥 Registered Users")
        users_df = get_all_users()
        st.dataframe(users_df, use_container_width=True, height=420)
        card_close()

    with tabs[2]:
        card_open()
        st.subheader("📝 Activity Logs")
        logs_df = load_activity_logs()
        st.dataframe(logs_df, use_container_width=True, height=420)
        card_close()

footer()