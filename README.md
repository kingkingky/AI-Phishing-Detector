# phishing-detector
Cybersecurity project for detecting phishing URLs and scam messages
# AI Phishing Detector

An AI-powered phishing detection system that analyzes URLs and predicts whether a website is legitimate or potentially malicious.

## Overview

Phishing attacks are one of the most common cybersecurity threats. This project uses Machine Learning techniques to analyze URL characteristics and identify suspicious websites.

The system provides a user-friendly web interface where users can submit URLs and receive instant risk assessments.

## Features

* URL phishing detection using Machine Learning
* Real-time website analysis
* Risk score generation
* User-friendly Flask web interface
* Feature extraction from URLs
* Prediction confidence display
* Detection history logging
* Security-focused dashboard

## Technologies Used

### Backend

* Python
* Flask
* Scikit-Learn
* Pandas
* NumPy
* Joblib

### Frontend

* HTML
* CSS
* JavaScript
* Bootstrap

### Machine Learning

* Random Forest Classifier
* Feature Engineering
* Data Preprocessing

## Project Structure

```
AI-Phishing-Detector/
│
├── app.py
├── model/
│   ├── phishing_model.pkl
│   └── preprocessor.pkl
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── dataset/
│   └── phishing_dataset.csv
│
├── train_model.py
├── requirements.txt
└── README.md
```

## Machine Learning Features

The model evaluates several URL characteristics:

* URL length
* Number of dots
* Number of special characters
* Presence of IP addresses
* HTTPS usage
* Suspicious keywords
* Subdomain count
* Domain characteristics

## Installation

1. Clone the repository

```bash
git clone https://github.com/yourusername/AI-Phishing-Detector.git
```

2. Install dependencies

```bash
pip install -r requirements.txt
```

3. Run the application

```bash
python app.py
```

4. Open browser

```text
http://127.0.0.1:5000
```

## Future Improvements

* WHOIS domain age analysis
* SSL certificate validation
* VirusTotal API integration
* Explainable AI dashboard
* Browser extension version
* Email phishing detection
* Deep Learning models
* Real-time threat intelligence feeds

## Results

The model successfully classifies URLs into:

* Legitimate Website
* Suspicious Website
* Phishing Website

## Author

Developed as a Cybersecurity and Machine Learning portfolio project.
