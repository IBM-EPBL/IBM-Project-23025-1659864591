import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle
#importing the inputScript file used to analyze the URL
import inputScript 


#load model
app = Flask(__name__)
model = pickle.load(open(r"C:\Users\Tharika\JSCODE\Web phishing detection\Flask\Phishing_website.pkl", 'rb'))

@app.route('/')
def helloworld():
    return render_template("homepage.html")

@app.route('/final')
def final():
    return render_template("Final.html")

@app.route('/homepage')
def homepage():
    return render_template("homepage.html")

@app.route('/about')
def about():
    return render_template("homepage.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")

#Redirects to the page to give the user input URL.
@app.route('/predict')
def predict():
    return render_template('Final.html')

#Fetches the URL given by the URL and passes to inputScript
@app.route('/y_predict',methods=['POST'])
def y_predict():
    '''
    For rendering results on HTML GUI
    '''
    url = request.form['URL']
    checkprediction = inputScript.main(url)
    print(checkprediction)
    prediction = model.predict(checkprediction)
    print(prediction)
    output=prediction[0]
    if(output==1):
        pred="Your are safe!!  This is a Legitimate Website."
        
    else:
        pred="You are on the wrong site. Be cautious!"
    return render_template('Final.html', prediction_text='{}'.format(pred),url=url)

#Takes the input parameters fetched from the URL by inputScript and returns the predictions
@app.route('/predict_api',methods=['POST'])
def predict_api():
    '''
    For direct API calls trought request
    '''
    data = request.get_json(force=True)
    prediction = model.y_predict([np.array(list(data.values()))])

    output = prediction[0]
    return jsonify(output)

if __name__ == "__main__":
    app.run( debug=True)