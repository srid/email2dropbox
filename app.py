import os
import logging
from flask import Flask
from flask import request
from flask import g
from postmark_inbound import PostmarkInbound

app = Flask(__name__)
app.debug = True

@app.route('/')
def hello():
    inmem = g.get('inmem', 'Nothing so far')
    return inmem, 200, {'Content-Type': 'text/plain'}

@app.route('/incoming', methods=['POST'])
def incoming():
    inbound = PostmarkInbound(json=request.get_data())
    g.inmem = "Received subject: %s" % inbound.subject()
    return "Ok"
