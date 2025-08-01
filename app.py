<<<<<<< HEAD
# /app.py
"""
Aegis: A Streamlit application for suspicious user login detection using AI.

This script combines data simulation, model training (Isolation Forest),
and an interactive Streamlit interface to analyze login activity.
"""

# 1. Imports
=======
>>>>>>> 7374075eb3899d67b401c18390c1d0e3699498bc
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
<<<<<<< HEAD
from faker import Faker
import joblib
import os
import plotly.express as px
import requests
from io import StringIO
import time
import ipaddress

# --- Configuration & Constants ---
MODEL_FILE = 'isolation_forest_model.joblib'
COLUMNS_FILE = 'model_columns.joblib'
DATA_FILE = 'simulated_logins.csv'

# --- 1. Simulated Dataset Generation ---
def generate_simulated_data(records=2000):
    """
    Generates a realistic-looking dataset of user login activity and saves it to a CSV.
    The dataset includes both normal and anomalous login patterns.
    """
    fake = Faker()
    data = []
    # Create a pool of 100 users with established "normal" behavior
    users = {
        fake.user_name(): {
            'country': fake.country(),
            'devices': [fake.user_agent() for _ in range(np.random.randint(1, 3))]
        } for _ in range(100)
    }

    for _ in range(records):
        username = np.random.choice(list(users.keys()))
        user_info = users[username]

        # 95% chance of normal behavior
        if np.random.rand() < 0.95:
            # Normal login: from their usual country and one of their usual devices
            timestamp = fake.date_time_this_year()
            ip_address = fake.ipv4()
            device_type = np.random.choice(user_info['devices'])
            location_country = user_info['country']
            location_city = fake.city()
        else:
            # Anomalous login: unusual time, new device, or new country
            timestamp = fake.date_time_this_year()
            # 50% chance of login at an odd hour (0-5 AM)
            if np.random.rand() < 0.5:
                timestamp = timestamp.replace(hour=np.random.randint(0, 6))

            ip_address = fake.ipv4()
            # 50% chance of a new device
            device_type = fake.user_agent() if np.random.rand() < 0.5 else np.random.choice(user_info['devices'])
            # 50% chance of a new country
            location_country = fake.country() if np.random.rand() < 0.5 else user_info['country']
            location_city = fake.city()

        data.append({
            "Username": username,
            "Timestamp": timestamp,
            "IP Address": ip_address,
            "Device Type": device_type,
            "Location (City)": location_city,
            "Location (Country)": location_country
        })

    df = pd.DataFrame(data)
    df.to_csv(DATA_FILE, index=False)
    return df

# --- New Helper Function for Feature Engineering ---
def simplify_device_type(user_agent):
    """Extracts a simplified OS and Browser from the user agent string."""
    ua = str(user_agent).lower()
    os = "Other"
    if "windows" in ua: os = "Windows"
    elif "macintosh" in ua or "mac os" in ua: os = "Mac OS"
    elif "linux" in ua: os = "Linux"
    elif "android" in ua: os = "Android"
    elif "iphone" in ua or "ipad" in ua: os = "iOS"

    browser = "Other"
    if "chrome" in ua: browser = "Chrome"
    elif "firefox" in ua: browser = "Firefox"
    elif "safari" in ua and "chrome" not in ua: browser = "Safari"
    elif "opera" in ua: browser = "Opera"
    elif "msie" in ua or "trident" in ua: browser = "IE"
    
    return f"{browser} on {os}"

# --- 2. Model Training & Feature Engineering ---
def feature_engineering(df):
    """Converts raw data into features suitable for the model."""
    # Ensure Timestamp is in datetime format
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df['hour_of_day'] = df['Timestamp'].dt.hour
    df['day_of_week'] = df['Timestamp'].dt.dayofweek

    # Simplify the user agent string to get a more general device/browser type
    df['Device Simplified'] = df['Device Type'].apply(simplify_device_type)

    # Combine location for easier encoding
    df['Location'] = df['Location (City)'].astype(str) + ", " + df['Location (Country)'].astype(str)

    return df

def train_model(df):
    """Trains an Isolation Forest model and saves it along with the feature columns."""
    df_featured = feature_engineering(df.copy())

    # Select features for the model
    features = ['hour_of_day', 'day_of_week', 'Username', 'Device Simplified', 'Location']
    df_model = df_featured[features]

    # One-Hot Encode categorical features
    df_encoded = pd.get_dummies(df_model, columns=['Username', 'Device Simplified', 'Location'])

    # Save the columns for later use during prediction to ensure consistency
    model_columns = df_encoded.columns.tolist()
    joblib.dump(model_columns, COLUMNS_FILE)

    # Train the Isolation Forest model
    # contamination='auto' is a robust default. A fixed value like 0.05 (for 5% anomalies)
    # can be used if you have a strong assumption about your data.
    model = IsolationForest(contamination='auto', random_state=42, n_estimators=100)
    model.fit(df_encoded)

    # Save the trained model
    joblib.dump(model, MODEL_FILE)

    return model, model_columns

# --- 5. Bonus: IP Geolocation API Integration ---
@st.cache_data(ttl=3600) # Cache results for 1 hour to avoid excessive API calls
def get_location_from_ip(ip_address):
    """Fetches geolocation for a given IP address using the ip-api.com service."""
    if ip_address in ['127.0.0.1', 'localhost'] or not ip_address:
        return "Localhost", "N/A"
    try:
        # The API is free and doesn't require a key
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        data = response.json()
        if data['status'] == 'success':
            return data.get('city', 'Unknown'), data.get('country', 'Unknown')
        else:
            return "Private/Unknown IP", "N/A"
    except requests.exceptions.RequestException as e:
        st.error(f"Geolocation API request failed: {e}")
        return "API Error", "API Error"

# --- Main Application Logic ---
def main():
    st.set_page_config(page_title="Aegis Login Detector", page_icon="🛡️", layout="wide")

    st.title("🛡️ Aegis: Suspicious Login Detection")
    st.write("An AI-powered app to detect anomalous user login activity using an Isolation Forest model.")

    # --- Model Loading / Initial Training ---
    if not os.path.exists(MODEL_FILE) or not os.path.exists(COLUMNS_FILE):
        with st.spinner("First-time setup: No model found. Generating data and training a new model... This may take a minute."):
            st.info("This is a one-time process. The trained model will be saved for future sessions.")
            simulated_data = generate_simulated_data()
            train_model(simulated_data)
            st.success("Model trained and saved successfully!")
            time.sleep(2) # Give user time to read the message
            st.experimental_rerun()
    else:
        model = joblib.load(MODEL_FILE)
        model_columns = joblib.load(COLUMNS_FILE)

    if 'login_history' not in st.session_state:
        st.session_state.login_history = pd.DataFrame(columns=[
            "Timestamp", "Username", "IP Address", "Device Type",
            "Location (City)", "Location (Country)", "Prediction"
        ])

    # --- 3. Streamlit Interface for Prediction ---
    st.sidebar.header("🔎 Analyze New Login(s)")
    input_method = st.sidebar.radio("Choose input method", ["Manual Entry", "Upload CSV"])

    new_login_data = None

    if input_method == "Manual Entry":
        with st.sidebar.form(key='manual_login_form'):
            username = st.text_input("Username", "john_doe")

            ip_version = st.radio("Select IP Version", ("IPv4", "IPv6"), horizontal=True)
            
            default_ip = "8.8.8.8" if ip_version == "IPv4" else "2001:db8::1"
            ip_address = st.text_input(f"Enter {ip_version} Address", default_ip)
            
            device_type = st.text_input("Device Type", "Chrome on Windows")

            submit_button = st.form_submit_button(label='Analyze Login')

            if submit_button:
                # --- IP Address Validation ---
                try:
                    ip_obj = ipaddress.ip_address(ip_address)
                    # Check if the entered version matches the selected radio button
                    if (ip_version == "IPv4" and not isinstance(ip_obj, ipaddress.IPv4Address)) or \
                       (ip_version == "IPv6" and not isinstance(ip_obj, ipaddress.IPv6Address)):
                        st.sidebar.error(f"'{ip_address}' is not a valid {ip_version} address. Please check your selection.")
                    else:
                        # If valid, proceed with analysis
                        with st.spinner("Fetching geolocation from IP..."):
                            city, country = get_location_from_ip(ip_address)
                        
                        new_login_data = pd.DataFrame([{
                            "Username": username,
                            "Timestamp": pd.Timestamp.now(tz='UTC'),
                            "IP Address": ip_address,
                            "Device Type": device_type,
                            "Location (City)": city,
                            "Location (Country)": country
                        }])
                except ValueError:
                    st.sidebar.error(f"Invalid IP address format: '{ip_address}'. Please enter a valid address.")

    elif input_method == "Upload CSV":
        uploaded_file = st.sidebar.file_uploader("Choose a CSV file", type="csv")
        if uploaded_file is not None:
            try:
                stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
                new_login_data = pd.read_csv(stringio)
                required_cols = {"Username", "Timestamp", "IP Address", "Device Type"}
                if not required_cols.issubset(new_login_data.columns):
                    st.error(f"CSV must contain at least these columns: {', '.join(required_cols)}")
                    new_login_data = None
                else:
                    if "Location (City)" not in new_login_data.columns: new_login_data["Location (City)"] = "Unknown"
                    if "Location (Country)" not in new_login_data.columns: new_login_data["Location (Country)"] = "N/A"
                    st.sidebar.success(f"Successfully loaded {len(new_login_data)} records from {uploaded_file.name}")
            except Exception as e:
                st.sidebar.error(f"Error processing CSV file: {e}")
                new_login_data = None

    # --- Prediction Logic ---
    if new_login_data is not None and not new_login_data.empty:
        df_processed = feature_engineering(new_login_data.copy())
        features_to_encode = ['Username', 'Device Simplified', 'Location']
        df_encoded = pd.get_dummies(df_processed, columns=features_to_encode)
        df_aligned = df_encoded.reindex(columns=model_columns, fill_value=0)
        
        predictions = model.predict(df_aligned[model_columns])
        new_login_data['Prediction'] = ['Suspicious' if p == -1 else 'Normal' for p in predictions]

        st.subheader("💡 Analysis Results")
        for index, row in new_login_data.iterrows():
            if row['Prediction'] == 'Suspicious':
                st.error(f"**Suspicious Login Detected!**\n"
                         f"- **User:** {row['Username']}\n"
                         f"- **Time:** {pd.to_datetime(row['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n"
                         f"- **IP:** {row['IP Address']} ({row.get('Location (City)', 'N/A')}, {row.get('Location (Country)', 'N/A')})\n"
                         f"- **Device:** {row['Device Type']}")
            else:
                st.success(f"**Normal Login Verified.**\n"
                           f"- **User:** {row['Username']} at {pd.to_datetime(row['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")

        st.session_state.login_history = pd.concat([new_login_data, st.session_state.login_history], ignore_index=True)
        st.session_state.login_history = st.session_state.login_history.head(1000)

    # --- 4. Dashboard Section ---
    st.markdown("---")
    st.header("📊 Login Activity Dashboard")

    if st.session_state.login_history.empty:
        st.info("No login data has been analyzed yet. Analyze a login to see the dashboard.")
    else:
        st.subheader("Recent Logins Analyzed")
        def highlight_suspicious(s):
            return ['background-color: #ff4b4b; color: white' if v == 'Suspicious' else '' for v in s]
        st.dataframe(st.session_state.login_history.style.apply(highlight_suspicious, subset=['Prediction']))

        st.subheader("Visualizations")
        col1, col2 = st.columns(2)

        with col1:
            st.write("Login Frequency by Hour")
            df_history_featured = feature_engineering(st.session_state.login_history.copy())
            hourly_counts = df_history_featured['hour_of_day'].value_counts().sort_index()
            fig_hourly = px.bar(x=hourly_counts.index, y=hourly_counts.values,
                                labels={'x': 'Hour of Day', 'y': 'Number of Logins'},
                                title="Login Counts per Hour")
            st.plotly_chart(fig_hourly, use_container_width=True)

        with col2:
            st.write("Suspicious vs. Normal Logins")
            prediction_counts = st.session_state.login_history['Prediction'].value_counts()
            fig_pie = px.pie(values=prediction_counts.values, names=prediction_counts.index,
                             title="Login Anomaly Distribution", color=prediction_counts.index,
                             color_discrete_map={'Suspicious':'#ff4b4b', 'Normal':'#28a745'})
            st.plotly_chart(fig_pie, use_container_width=True)

    # --- Model Management ---
    st.sidebar.markdown("---")
    st.sidebar.subheader("Model Management")
    if st.sidebar.button("Retrain Model"):
        with st.spinner("Retraining model with new simulated data..."):
            simulated_data = generate_simulated_data()
            train_model(simulated_data)
            st.sidebar.success("Model retrained successfully!")
            time.sleep(2)
            st.experimental_rerun()

# --- Entry point of the script ---
if __name__ == "__main__":
    main()
=======
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
>>>>>>> 7374075eb3899d67b401c18390c1d0e3699498bc
