from flask import Flask, render_template, request, jsonify
import pickle
import os

app = Flask(__name__)

# ── Load model and vectorizer ────────────────────────────
model      = pickle.load(open('phishing_model.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    email_text = request.form.get('email_text', '')

    if not email_text.strip():
        return jsonify({'error': 'Please enter email text'})

    # Vectorize and predict
    vectorized  = vectorizer.transform([email_text])
    prediction  = model.predict(vectorized)[0]
    probability = model.predict_proba(vectorized)[0]

    threat_prob = round(probability[1] * 100, 2)
    safe_prob   = round(probability[0] * 100, 2)

    # ── category: used by HTML to colour the threat-type pill ──
    text_lower = email_text.lower()
    if any(k in text_lower for k in ['../','etc/passwd','union select','<script',
                                      'cmd=','exec(','sql','drop table']):
        category = 'intrusion'
    elif any(k in text_lower for k in ['.exe','.bat','download','install now',
                                        'run setup','ransomware','trojan','virus']):
        category = 'malware'
    else:
        category = 'phishing'   # default — matches training data

    return jsonify({
        'prediction':        int(prediction),          # 0 or 1
        'label':             'PHISHING' if prediction == 1 else 'SAFE',
        'category':          category if prediction == 1 else 'safe',
        'threat_probability': threat_prob,             # JS reads data.threat_probability
        'safe_probability':   safe_prob,               # JS reads data.safe_probability
    })

if __name__ == '__main__':
    app.run(debug=True)
