from flask import Flask, render_template, request
from analyzer import detect_encryption

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return 'No file part in the request.'

    file = request.files['file']
    if file.filename == '':
        return 'No selected file.'

    code = file.read().decode('utf-8')
    detected = detect_encryption(code)

    return render_template('index.html', result=detected, code=code)

if __name__ == '__main__':
    app.run(debug=True)
