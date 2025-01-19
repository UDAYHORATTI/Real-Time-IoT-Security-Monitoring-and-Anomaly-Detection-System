# Real-Time-IoT-Security-Monitoring-and-Anomaly-Detection-System
The Real-Time IoT Security Monitoring and Anomaly Detection System is a tool designed to monitor and analyze data traffic and activities within an IoT network in real-time. It aims to detect anomalous behaviors such as unusual network traffic,
import scapy.all as scapy
from sklearn.ensemble import IsolationForest
from flask import Flask, render_template, jsonify
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
import sqlite3
import logging
import time

# Setup logging
logging.basicConfig(filename='iot_security_monitoring_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Flask app for dashboard
app = Flask(__name__)

# Twilio credentials for SMS alerts
TWILIO_SID = "your_twilio_sid"
TWILIO_AUTH_TOKEN = "your_twilio_auth_token"
TWILIO_PHONE = "your_twilio_phone"
ADMIN_PHONE = "admin_phone_number"

# Email credentials for sending alerts
EMAIL_ADDRESS = "your_email@example.com"
EMAIL_PASSWORD = "your_email_password"
ADMIN_EMAIL = "admin_email@example.com"

# Function to monitor network traffic and extract features
def monitor_network():
    traffic_data = []
    # Capture packets for a period of time
    for packet in scapy.sniff(timeout=10):
        # Collecting packet features (e.g., size, protocols, flags)
        packet_info = [len(packet), packet.proto]
        traffic_data.append(packet_info)
    return traffic_data

# Function to detect anomalies using Isolation Forest
def detect_anomalies(data):
    model = IsolationForest(contamination=0.1)  # Assume 10% of the data could be anomalies
    model.fit(data)
    predictions = model.predict(data)
    return predictions

# Function to send email alerts
def send_email_alert(message):
    msg = MIMEText(message)
    msg['Subject'] = 'IoT Security Alert'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = ADMIN_EMAIL

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, ADMIN_EMAIL, msg.as_string())

# Function to send SMS alerts
def send_sms_alert(message):
    client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
    client.messages.create(
        body=message,
        from_=TWILIO_PHONE,
        to=ADMIN_PHONE
    )

# Function to log detected anomalies
def log_anomaly(packet_info, anomaly_label):
    conn = sqlite3.connect('iot_devices.db')
    c = conn.cursor()
    c.execute("INSERT INTO anomalies (packet_info, anomaly_label) VALUES (?, ?)", (str(packet_info), anomaly_label))
    conn.commit()
    conn.close()

# Function to create a simple dashboard (Flask app)
@app.route('/')
def dashboard():
    conn = sqlite3.connect('iot_devices.db')
    c = conn.cursor()
    c.execute("SELECT * FROM anomalies")
    anomalies = c.fetchall()
    conn.close()
    return render_template('dashboard.html', anomalies=anomalies)

# Main function to start monitoring
def start_monitoring():
    while True:
        traffic_data = monitor_network()
        anomalies = detect_anomalies(traffic_data)

        # Log and respond to detected anomalies
        for i, anomaly in enumerate(anomalies):
            if anomaly == -1:  # Anomaly detected
                anomaly_info = traffic_data[i]
                logging.warning(f"Anomaly detected: {anomaly_info}")
                log_anomaly(anomaly_info, 'Anomaly Detected')

                # Send email and SMS alerts
                send_email_alert(f"Anomaly detected: {anomaly_info}")
                send_sms_alert(f"Anomaly detected: {anomaly_info}")

        time.sleep(10)  # Sleep for 10 seconds before next iteration

# Run Flask app for dashboard
if __name__ == "__main__":
    app.run(debug=True)

