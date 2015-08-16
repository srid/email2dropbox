import os
from contextlib import contextmanager
import logging
log = logging.getLogger(__name__)

from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
import pyramid.httpexceptions as exc
from pyramid.session import SignedCookieSessionFactory

from dropbox.client import DropboxOAuth2Flow, DropboxClient
from postmark_inbound import PostmarkInbound


@view_config(name='', request_method='GET')
def index(request):
    flow = make_dropbox_auth_flow(request.session)
    authorize_url = flow.start()
    return exc.HTTPFound(location=authorize_url)

@view_config(name='dropboxauth', request_method='POST')
def dropboxauth(request):
    with handle_dropbox_redirect():
        flow = make_dropbox_auth_flow(request.session)
        access_token, user_id, url_state = flow.finish(request.GET)
    return HTTPFound(location="/home")

@view_config(name='incoming', request_method='POST')
def incoming(request):
    inbound = PostmarkInbound(json=request.body)
    log.error("Received email: %s", inbound.subject())
    return Response("Ok")


def configure_webapp():
    session_secret = os.getenv("SESSION_SECRET")
    if session_secret is None:
        raise ValueError("session secret not set")

    config = Configurator()
    config.scan()
    session_factory = SignedCookieSessionFactory(session_secret)
    config.set_session_factory(session_factory)

    app = config.make_wsgi_app()

    h = logging.StreamHandler()
    h.setLevel(logging.DEBUG)
    log.addHandler(h)

    port = int(os.environ.get("PORT", 8080))
    return make_server('0.0.0.0', port, app)

def configure_dropbox():
    app_key = os.getenv("DROPBOX_APP_KEY")
    app_secret = os.getenv("DROPBOX_APP_SECRET")
    if app_key is None or app_secret is None:
        raise ValueError("DROPBOX env vars not set")
    return app_key, app_secret

def make_dropbox_auth_flow(session):
    app_key, app_secret = configure_dropbox()
    flow = DropboxOAuth2Flow(app_key, app_secret,
                             request.session, "dropbox-auth-csrf-token")
    return flow

@contextmanager
def handle_dropbox_redirect():
    try:
        yield
    except DropboxOAuth2Flow.BadRequestException, e:
        raise exc.HTTPBadRequest()
    except DropboxOAuth2Flow.BadStateException, e:
        log.info('Bad state; trying again.')
        # Start the auth flow again.
        pass # return HTTPFound(location="/home")
    except DropboxOAuth2Flow.CsrfException, e:
        raise exc.HTTPForbidden()
    except DropboxOAuth2Flow.NotApprovedException, e:
        log.error('Not approved?  Why not?')
        pass # return HTTPFound(location="/home")
    except DropboxOAuth2Flow.ProviderException, e:
        log.error("Auth error: %s" % (e,))
        raise exc.HTTPForbidden()

if __name__ == '__main__':
    configure_dropbox()
    server = configure_webapp()
    log.error("Running Pyramid at http://0.0.0.0:$PORT")
    server.serve_forever()
