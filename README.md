# 🛡️ Aegis: AI-Powered Suspicious Login Detection

Aegis is an interactive web application built with Streamlit that uses an Isolation Forest machine learning model to detect suspicious user login activity. It provides a simple interface for security analysts or administrators to analyze login events in real-time.

![Aegis Screenshot](placeholder.png) <!-- It's a good practice to add a screenshot of your running app -->

---

## ✨ Features

*   **AI-Powered Anomaly Detection**: Utilizes `scikit-learn`'s `IsolationForest` to identify unusual login patterns based on time, location, and device.
*   **Multiple Input Methods**:
    *   **Manual Entry**: Quickly analyze a single login event with IP version selection (IPv4/IPv6) and validation. Supports manual overrides for login time and location, and tracking of login success status.
    *   **CSV Upload**: Batch process multiple login events from a CSV file.
*   **IP Geolocation**: Automatically enriches IP addresses with city and country data using a free public API.
*   **Interactive Dashboard**:
    *   Displays a table of recently analyzed logins with clear "Normal" or "Suspicious" labels.
    *   Visualizes login frequency by hour and the distribution of normal vs. suspicious events.
*   **Automatic Model Training**: On first run, the app simulates a realistic dataset and trains the detection model, saving it for future use.
*   **Model Management**: Includes an option to retrain the model on new simulated data directly from the UI.

---

## 🚀 How It Works

1.  **Data Simulation & Training (First Run)**: If no model exists, the app generates a `simulated_logins.csv` file with both normal and anomalous login patterns. It then trains an `IsolationForest` model on this data, considering features like hour of day, day of week, username, device type, and location. The trained model (`isolation_forest_model.joblib`) and its feature columns are saved locally.
2.  **Feature Engineering**: For each new login, the app converts raw data (like timestamps and user-agent strings) into numerical and categorical features that the model can understand using a robust parsing function.
3.  **Prediction**: The processed features of the new login are fed into the pre-trained model. The model returns a score indicating whether the event is an inlier (Normal) or an outlier (Suspicious).
4.  **Visualization**: The results are displayed in the Streamlit interface with color-coded alerts and are added to a dashboard for a high-level overview of login activity.

---

## 🛠️ Setup and Installation

Before you begin, ensure you have Python 3.7+ installed.

1.  **Clone the repository (or download the files):**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required libraries:**
    ```bash
    pip install streamlit pandas scikit-learn joblib faker plotly requests shap "numpy<2.0"
    ```

---

## 🏃‍♀️ Running the App

To start the Streamlit application, run the following command in your terminal:

```bash
streamlit run app.py
```

Your web browser will automatically open with the Aegis application running.

> **Note:** The first time you run the app, it will take a moment to generate the simulated data and train the model. This is a one-time process.

---

## 📂 File Structure

*   `app.py`: The main Streamlit application script containing all the logic.
*   `simulated_logins.csv` (auto-generated): The dataset used for training the model.
*   `isolation_forest_model.joblib` (auto-generated): The saved, pre-trained machine learning model.
*   `model_columns.joblib` (auto-generated): A list of feature columns used during training to ensure consistency during prediction.
*   `README.md`: This file.