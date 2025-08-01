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

# --- 2. Model Training & Feature Engineering ---
def feature_engineering(df):
    """Converts raw data into features suitable for the model."""
    # Ensure Timestamp is in datetime format and standardized to UTC
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], utc=True)
    df['hour_of_day'] = df['Timestamp'].dt.hour
    df['day_of_week'] = df['Timestamp'].dt.dayofweek

    # Simplify the user agent string to get a more general device/browser type
    df['Device Simplified'] = df['Device Type'].apply(lambda x: str(x).split(')')[0].split('(')[-1].split('/')[0])

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
    model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
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
            st.rerun()
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
    input_method = st.sidebar.radio(
        "Choose input method:",
        ["Manual Entry", "Upload CSV"],
        horizontal=True
    )

    new_login_data = None
    show_normal_logins = True

    if input_method == "Manual Entry":
        with st.sidebar.form(key='manual_login_form'):
            username = st.text_input("Username", "john_doe")

            ip_version = st.radio("Select IP Version:", ("IPv4", "IPv6"), horizontal=True)
            default_ip = "8.8.8.8" if ip_version == "IPv4" else "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
            ip_address = st.text_input(f"Enter {ip_version} Address", default_ip)
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
                if len(new_login_data) > 5:
                    show_normal_logins = False
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

    # --- Analysis Results ---
    if new_login_data is not None and not new_login_data.empty:
        st.subheader("💡 Analysis Results")
        suspicious_count = 0
        successful_logins = 0
        for index, row in new_login_data.iterrows():
            if row['Prediction'] == 'Suspicious':
                suspicious_count += 1
                st.error(f"**Suspicious Login Detected!**\n"
                         f"- **User:** {row['Username']}\n"
                         f"- **Time:** {pd.to_datetime(row['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n"
                         f"- **IP:** {row['IP Address']} ({row.get('Location (City)', 'N/A')}, {row.get('Location (Country)', 'N/A')})\n"
                         f"- **Device:** {row['Device Type']}")
            else:
                successful_logins += 1
                # st.success(f"**Normal Login Verified.**\n"
                #            f"- **User:** {row['Username']} at {pd.to_datetime(row['Timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        st.success(f"**Normal Login Verified for {successful_logins} users**\n")
        if not show_normal_logins and suspicious_count == 0:
            st.info("No suspicious logins were detected in the uploaded file.")

    # --- Model Management ---
    st.sidebar.markdown("---")
    st.sidebar.subheader("Model Management")

    training_data = None
    uploaded_training_file = st.sidebar.file_uploader(
        "Upload Training Data (CSV)",
        type="csv",
        help="Upload a CSV with login data to train the model. If not provided, synthetic data will be generated."
    )

    if uploaded_training_file is not None:
        try:
            stringio = StringIO(uploaded_training_file.getvalue().decode("utf-8"))
            training_data = pd.read_csv(stringio)
            st.sidebar.success(f"Successfully loaded {len(training_data)} records for training.")
        except Exception as e:
            st.sidebar.error(f"Error processing training file: {e}")
            training_data = None

    if st.sidebar.button("Retrain Model"):
        if training_data is not None:
            with st.spinner("Retraining model with uploaded data..."):
                train_model(training_data)
                st.sidebar.success("Model retrained successfully!")
        else:
            with st.spinner("Retraining model with new simulated data..."):
                simulated_data = generate_simulated_data()
                train_model(simulated_data)
                st.sidebar.success("Model retrained successfully!")
        
        time.sleep(2)
        st.rerun()

# --- Entry point of the script ---
if __name__ == "__main__":
    main()