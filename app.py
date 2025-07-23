import streamlit as st
import joblib
import numpy as np
import urllib.parse
import socket
import requests
from bs4 import BeautifulSoup
import pandas as pd
import re

model = joblib.load("decision_tree_model.pkl")
scaler = joblib.load("scaler.pkl")  

# === URL Validity Check ===
def is_valid_url(url):
    regex = re.compile(
        r'^(https?|ftp):\/\/'
        r'(([a-zA-Z0-9$-_@.&+!\*\(\),]+)'
        r'(:[a-zA-Z0-9$-_@.&+!\*\(\),]+)?@)?'  # user:pass authentication
        r'(([0-9]{1,3}\.){3}[0-9]{1,3}'  # IP address
        r'|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))'  # domain
        r'(:[0-9]{1,5})?'  # port
        r'((\/[-a-zA-Z0-9%_.~+]*)*'  # path
        r'(\?[;&a-zA-Z0-9%_.~+=-]*)?'  # query
        r'(\#[-a-zA-Z0-9_]*)?)$', re.IGNORECASE)
    return re.match(regex, url) is not None


def having_IP(url):
    try:
        socket.inet_aton(urllib.parse.urlparse(url).netloc)
        return -1
    except socket.error:
        return 1

def having_At_Symbol(url):
    return -1 if '@' in url else 1

def URL_Length(url):
    return -1 if len(url) >= 54 else 1

def Prefix_Suffix(url):
    return -1 if '-' in urllib.parse.urlparse(url).netloc else 1

def DNSRecord(url):
    try:
        domain = urllib.parse.urlparse(url).netloc
        socket.gethostbyname(domain)
        return 1
    except:
        return -1

def SSLfinal_State(url):
    return 1 if url.startswith("https") else -1

def Favicon(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        icon_link = soup.find("link", rel="shortcut icon") or soup.find("link", rel="icon")
        if icon_link:
            icon_url = urllib.parse.urljoin(url, icon_link["href"])
            return 1 if urllib.parse.urlparse(icon_url).netloc in url else -1
    except:
        return -1

def Request_URL(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        total = len(soup.find_all(['img', 'script', 'link']))
        external = sum(1 for tag in soup.find_all(['img', 'script', 'link'])
                       if urllib.parse.urlparse(tag.get('src', '')).netloc not in url)
        return 1 if (total > 0 and external / total < 0.5) else -1
    except:
        return -1

def URL_of_Anchor(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        total = len(soup.find_all('a'))
        external = sum(1 for a in soup.find_all('a')
                       if urllib.parse.urlparse(a.get('href', '')).netloc not in url)
        return 1 if (total > 0 and external / total < 0.5) else -1
    except:
        return -1

def popupWindow(url):
    try:
        response = requests.get(url, timeout=5)
        return -1 if "window.open" in response.text.lower() else 1
    except:
        return -1



def predict_url(url):
    if not is_valid_url(url):
        return "⚠️ Invalid URL"
    
    features = [
        having_IP(url),
        having_At_Symbol(url),
        URL_Length(url),
        Prefix_Suffix(url),
        DNSRecord(url),
        SSLfinal_State(url),
        Favicon(url),
        Request_URL(url),
        URL_of_Anchor(url),
        popupWindow(url)
    ]

   
    features_scaled = scaler.transform([features])
    prediction = model.predict(features_scaled)

    return "✅ SAFE" if prediction[0] == 1 else "🚨 PHISHING"


st.markdown(
    """
    <style>
        body {
            background-color: #f4f4f4;
        }
        .title {
            font-size: 28px;
            font-weight: bold;
            text-align: center;
            color: #ffffff;
            background-color: #1f77b4;
            padding: 15px;
            border-radius: 10px;
        }
        .stTextInput>div>div>input {
            border: 2px solid #1f77b4 !important;
            border-radius: 10px;
            padding: 8px;
        }
        .stButton>button {
            background-color: #1f77b4;
            color: white;
            border-radius: 10px;
            font-size: 16px;
            padding: 10px;
            width: 100px;
            gap: 100px
        }
        .stButton>button:hover {
            background-color: #125688;
        }
        .prediction-box {
            text-align: center;
            font-size: 20px;
            font-weight: bold;
            color: #fff;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .safe {
            background-color: #28a745;
        }
        .phishing {
            background-color: #dc3545;
        }
        .subtitle{
            text-align: center;
        }
        
        .content{
            text-align: center;
        }
        
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown('<p class="title">DEPARTMENT OF INFORMATION TECHNOLOGY</p>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">NATIONAL INSTITUTE OF TECHNOLOGY KARNATAKA, SURATHKAL-575025</p>', unsafe_allow_html=True)

st.markdown('<p class="content"><b>Information Assurance and Security (IT352) Course Project</b></p>', unsafe_allow_html=True)
st.markdown('<p class="content"><b>Carried out by</b></p>', unsafe_allow_html=True)
st.markdown('<p class="content">Sonali Kannojiya (221IT065)</p>', unsafe_allow_html=True)
st.markdown('<p class="content">Kunchala Lakshmi Sanjana (221IT041)</p>', unsafe_allow_html=True)
st.markdown('<p class="content">During Academic Session January – April 2025</p>', unsafe_allow_html=True)

st.title("🔍 Phishing URL Detection")
st.write("Enter a URL to check whether it is phishing or legitimate.")


url = st.text_input("Enter URL:")

if st.button("Predict"):
    if not is_valid_url(url):
        st.warning("⚠️ Please enter a valid URL!")
    else:
        with st.spinner("Analyzing URL..."):
            result = predict_url(url)
            if result == "✅ SAFE":
                st.success(result)
            else:
                st.error(result)

        result_df = pd.DataFrame({"URL": [url], "Prediction": [result]})
        output_filename = "single_url_result.csv"
        result_df.to_csv(output_filename, index=False)
        st.download_button(
            label="📥 Download Result",
            data=open(output_filename, "rb").read(),
            file_name=output_filename,
            mime="text/csv"
        )



uploaded_file = st.file_uploader("Upload file containing list of URLs:", type=["csv", "xlsx"])
if uploaded_file:
    file_extension = uploaded_file.name.split(".")[-1].lower()
    
    if file_extension == "csv":
        df = pd.read_csv(uploaded_file)
    elif file_extension == "xlsx":
        df = pd.read_excel(uploaded_file)
    else:
        st.error("Unsupported file format!")
        st.stop()
    
    if "URL" in df.columns:
        df["Prediction"] = df["URL"].apply(predict_url)
        st.write(df)
        
        if st.button("Store Results"):
            output_filename = f"phishing_results.{file_extension}"
            if file_extension == "csv":
                df.to_csv(output_filename, index=False)
                mime_type = "text/csv"
            else:
                df.to_excel(output_filename, index=False)
                mime_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            
            st.success("✅ Results stored successfully!")
            st.download_button(
                label="📥 Download Results",
                data=open(output_filename, "rb").read(),
                file_name=output_filename,
                mime=mime_type
            )
    else:
        st.error("Invalid file format! Ensure the file has a column named 'URL'.")