#https://flask.palletsprojects.com/en/1.1.x/quickstart/#quickstart
from flask import Flask, request
from flask_cors import CORS
import joblib
import re
from feature_extract import getFeatures
import numpy as np

app = Flask(__name__)
CORS(app)

CLASSIFIER = joblib.load('./saved_models/rf.pkl')


@app.route('/')
def test():
    return 'API for Predicting Phishing URL!!!'

@app.route('/predict', methods=['POST'])
def predict_url():
    # get url from the body sent
    url = request.json['url'] if request.json['url'] else None
    print('got request', url)
    # check if url exists or not, if not then send an error response
    if not url:
        return 'URL is missing! URL is required to predict', 500
    # check if the url is starting with http/https/ftp/ftps
    if not(re.search(r'^(http|ftp)s?://', url)):
        return 'Not a valid URL. Ex: https://google.com', 500
    
    #Now get features from the url
    feature_list = getFeatures(url)
    if feature_list[7] == -1:
        return str(-1)
    features = np.array(feature_list).reshape(1, -1)
    #pass the features to classifier to predict the result
    predited_result = CLASSIFIER.predict(features)

    # return the result as respone to API request
    # 1 means legitimate, -1 means phishing
    print(predited_result[0])
    return str(predited_result[0])
