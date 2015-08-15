import os
import logging
log = logging.getLogger(__name__)

from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response

from postmark_inbound import PostmarkInbound


def index(request):
    return Response('Hello world')

def incoming(request):
    inbound = PostmarkInbound(json=request.body)
    log.error("Received subject: %s", inbound.subject())
    return Response("Ok")


if __name__ == '__main__':
    config = Configurator()
    config.add_route('index', '/')
    config.add_view(index, route_name='index')
    config.add_route('webhook', '/incoming')
    config.add_view(incoming, route_name='webhook')
    app = config.make_wsgi_app()
    port = int(os.environ.get("PORT", 8080))
    server = make_server('0.0.0.0', port, app)
    server.serve_forever()
