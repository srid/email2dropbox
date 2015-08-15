import os
import logging
log = logging.getLogger(__name__)

from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config

from postmark_inbound import PostmarkInbound


@view_config(name='', request_method='GET')
def index(request):
    return Response('Nothing here, move along')

@view_config(name='incoming', request_method='POST')
def incoming(request):
    inbound = PostmarkInbound(json=request.body)
    log.error("Received email: %s", inbound.subject())
    return Response("Ok")

if __name__ == '__main__':
    config = Configurator()
    config.scan()
    app = config.make_wsgi_app()

    h = logging.StreamHandler()
    h.setLevel(logging.DEBUG)
    log.addHandler(h)

    port = int(os.environ.get("PORT", 8080))
    server = make_server('0.0.0.0', port, app)
    server.serve_forever()
