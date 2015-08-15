import os
from flask import Flask
from flask import request

app = Flask(__name__)

@app.route('/')
def hello():
    return '\n'.join(map(str, os.environ.items()))

@app.route('/incoming', methods=['POST'])
def incoming():
    return request.get_data()
