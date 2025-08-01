import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime
import random
import pytz

# --- Configuration ---
st.set_page_config(
    page_title="Account Sentinel",
    page_icon="🛡️",
    layout="wide"
)

MODEL_DIR = "ml_models"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_model.joblib")
GEOIP_DB_PATH = "geoip_db/GeoLite2-City.mmdb"

# --- GeoIP Setup ---
try:
    import geoip2.database
    geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    GEOIP_LOADED = True
except (FileNotFoundError, ImportError):
    GEOIP_LOADED = False

# --- Caching Model and Data ---
@st.cache_resource
def load_model_and_artifacts():
    """
    Loads the trained model and artifacts from disk. If not found,
    it generates data and trains a new one.
    """
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)

    st.info("Model not found. Generating synthetic data and training a new model...")
    os.makedirs(MODEL_DIR, exist_ok=True)

    # 1. Generate Data
    normal_logins = {
        'ip_address': ['8.8.8.8', '1.1.1.1', '208.67.222.222'] * 100,
        'user_agent': ['Chrome_Windows', 'Firefox_Windows', 'Safari_Mac'] * 100,
        'hour': np.random.normal(14, 4, 300).astype(int) % 24, # Peak at 2 PM
        'day_of_week': np.random.randint(0, 5, 300) # Weekdays
    }
    anomalous_logins = {
        'ip_address': ['198.51.100.55', '203.0.113.123', '192.0.2.100'] * 5,
        'user_agent': ['curl/7.64.1', 'python-requests/2.25.1', 'Nmap Scripting Engine'] * 5,
        'hour': np.random.randint(0, 6, 15), # Late night / early morning
        'day_of_week': np.random.randint(0, 7, 15) # Any day
    }
    df = pd.concat([pd.DataFrame(normal_logins), pd.DataFrame(anomalous_logins)], ignore_index=True)

    # 2. Feature Engineering
    df['ip_code'] = pd.factorize(df['ip_address'])[0]
    df['ua_code'] = pd.factorize(df['user_agent'])[0]
    features = df[['hour', 'day_of_week', 'ip_code', 'ua_code']]

    # 3. Train Model
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(features_scaled)

    # 4. Save Artifacts
    artifacts = {
        'model': model,
        'scaler': scaler,
        'ip_map': dict(zip(df['ip_address'], df['ip_code'])),
        'user_agent_map': dict(zip(df['user_agent'], df['ua_code'])),
    }
    joblib.dump(artifacts, MODEL_PATH)
    st.success("New model trained and saved!")
    return artifacts

def get_location(ip):
    """Looks up the location of an IP address."""
    if not GEOIP_LOADED or not ip:
        return "N/A", None, None
    try:
        response = geoip_reader.city(ip)
        lat = response.location.latitude
        lon = response.location.longitude
        location_str = f"{response.city.name}, {response.country.name}"
        return location_str, lat, lon
    except Exception:
        return "Local/Unknown IP", None, None

# --- Main App ---

st.title("🛡️ Account Sentinel")
st.write("An interactive dashboard to detect suspicious user logins using an Isolation Forest model.")

artifacts = load_model_and_artifacts()
model = artifacts['model']
scaler = artifacts['scaler']
ip_map = artifacts['ip_map']
ua_map = artifacts['user_agent_map']

# Initialize session state for login history
if 'login_history' not in st.session_state:
    st.session_state.login_history = []

# --- Sidebar for Login Simulation ---
with st.sidebar:
    st.header("Simulate a New Login")
    username = st.text_input("Username", "demo_user")
    
    # Provide some known and unknown IPs for easy testing
    ip_options = list(ip_map.keys())[:3] + ["104.26.10.238", "1.2.3.4"]
    ip_address = st.selectbox("IP Address", ip_options)
    
    ua_options = list(ua_map.keys())[:3] + ["curl/7.81.0", "PostmanRuntime/7.29.2"]
    user_agent = st.selectbox("User Agent (Device)", ua_options)

    if st.button("Analyze Login", type="primary"):
        now = datetime.now(pytz.utc)
        
        # Preprocess new data
        ip_code = ip_map.get(ip_address, -1) # Use -1 for unknown
        ua_code = ua_map.get(user_agent, -1)
        
        login_data = pd.DataFrame([{
            'hour': now.hour,
            'day_of_week': now.weekday(),
            'ip_code': ip_code,
            'ua_code': ua_code
        }])
        
        # Predict
        features_scaled = scaler.transform(login_data)
        prediction = model.predict(features_scaled)
        
        # Determine status
        if ip_code == -1 or ua_code == -1:
            status = "Unknown"
            details = "New IP or device detected."
        elif prediction[0] == -1:
            status = "Suspicious"
            details = "Login flagged as anomalous by model."
        else:
            status = "Normal"
            details = "Login behavior is consistent."
            
        # Get location
        location, lat, lon = get_location(ip_address)

        # Store result
        st.session_state.login_history.insert(0, {
            "Timestamp": now,
            "Username": username,
            "Status": status,
            "IP Address": ip_address,
            "Location": location,
            "Device": user_agent,
            "Details": details,
            "lat": lat,
            "lon": lon
        })
        
        # Show feedback
        if status == "Suspicious":
            st.error(f"**Suspicious Login Detected!**\n\n{details}")
        elif status == "Unknown":
            st.warning(f"**Unknown Login Pattern**\n\n{details}")
        else:
            st.success(f"**Normal Login**\n\n{details}")

# --- Dashboard Display ---
st.header("Recent Login Activity")

if not st.session_state.login_history:
    st.info("No logins simulated yet. Use the sidebar to analyze a new login.")
else:
    history_df = pd.DataFrame(st.session_state.login_history)

    # --- Dataframe with colored status ---
    def style_status(row):
        if row.Status == "Suspicious":
            return ['background-color: #ffadad'] * len(row)
        elif row.Status == "Unknown":
            return ['background-color: #ffd6a5'] * len(row)
        return [''] * len(row)

    st.dataframe(
        history_df[['Timestamp', 'Username', 'Status', 'IP Address', 'Location', 'Device', 'Details']].style.apply(style_status, axis=1),
        use_container_width=True,
        hide_index=True
    )

    # --- Activity Analytics ---
    st.header("Activity Analytics")

    # Ensure Timestamp is in datetime format for plotting
    history_df['Timestamp'] = pd.to_datetime(history_df['Timestamp'])

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Logins by Status")
        status_counts = history_df['Status'].value_counts()

        # To color bars based on category, we must format the data correctly.
        # st.bar_chart colors by column, so we need to make each status a column.
        color_map = {
            "Suspicious": "#ffadad",  # Red
            "Unknown": "#ffd6a5",     # Yellow
            "Normal": "#a5d6a7",      # Green
        }

        # Transpose value_counts to get statuses as columns
        chart_data = pd.DataFrame(status_counts).T
        # Create a list of colors in the same order as the columns
        chart_colors = [color_map.get(col, "#808080") for col in chart_data.columns]

        st.bar_chart(chart_data, color=chart_colors)
    with col2:
        st.subheader("Logins by Hour of Day")
        hourly_counts = history_df['Timestamp'].dt.hour.value_counts().sort_index()
        st.bar_chart(hourly_counts)

    st.subheader("Login Trend Over Time")
    logins_per_day = history_df.set_index('Timestamp').resample('D').size().rename('Total Logins')
    st.line_chart(logins_per_day)

    # --- Map of Login Locations ---
    st.subheader("Login Locations")
    map_df = history_df.dropna(subset=['lat', 'lon'])

    if not map_df.empty:
        st.map(map_df)
    else:
        st.write("No location data available to display on the map.")

if not GEOIP_LOADED:
    st.warning("GeoIP database not found at `geoip_db/GeoLite2-City.mmdb`. Location features are disabled.")