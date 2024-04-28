# Import necessary libraries
from flask import Flask, render_template, request
import pickle
from urllib.parse import urlparse
from tld import get_tld
import re

# Initialize Flask app
app = Flask(__name__)

# Load the pre-trained model
with open('random_forest_model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

# Function to preprocess URL and extract features
def preprocess_url(url):
    parsed_url = urlparse(url)
    url_length = len(url)
    hostname_length = len(parsed_url.netloc)
    path_length = len(parsed_url.path)
    fd_length = 0
    try:
        fd_length = len(parsed_url.path.split('/')[1])
    except:
        pass
    tld = get_tld(url, fail_silently=True)
    tld_length = len(tld) if tld else -1
    features = [url_length, hostname_length, path_length, fd_length, tld_length]
    
    # Additional features extracted from the URL
    features += [url.count('@'), url.count('?'), url.count('-'), url.count('='), url.count('.'),
                 url.count('#'), url.count('%'), url.count('+'), url.count('$'), url.count('!'),
                 url.count('*'), url.count(','), url.count('//'), url.count('http'), url.count('https'),
                 sum(c.isdigit() for c in url), sum(c.isalpha() for c in url), url.count('/')]
    
    # Features related to IP address and URL shortening service
    features += [having_ip_address(url), shortening_service(url)]
    
    return features

# Function to check if IP address is present in URL
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
        url)  # Ipv6
    if match:
        return -1
    else:
        return 1

# Function to check if URL is from a URL shortening service
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return -1
    else:
        return 1

# Define home route
@app.route('/')
def home():
    return render_template('index.html')

# Define predict route
@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    # Preprocess the URL
    features = preprocess_url(url)
    # Make prediction using the loaded model
    prediction = model.predict([features])[0]
    # Determine prediction label
    prediction_label = "Malicious" if prediction == 1 else "Benign"
    return render_template('result.html', prediction=prediction_label)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
