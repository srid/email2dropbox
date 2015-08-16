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

import dropbox.rest
from dropbox.client import DropboxOAuth2Flow, DropboxClient
from postmark_inbound import PostmarkInbound


# Inbound email handling
# ----------------------

def handle_email(message):
    # `message` is of format: https://github.com/jpadilla/postmark-inbound-python#usage
    log.error("Received email from %s", message.sender())
    log.error("Message JSON: %s", message.json)
    dropbox_append("/log.txt", message.text_body())


# HTTP view handling
# ------------------

@view_config(request_method='GET')
def index(request):
    flow = make_dropbox_auth_flow(request.session, dropboxauth_url(request))
    authorize_url = flow.start()
    return exc.HTTPFound(location=authorize_url)

@view_config(name='dropboxauth', request_method='GET')
def dropboxauth(request):
    with handle_dropbox_redirect():
        flow = make_dropbox_auth_flow(request.session, dropboxauth_url(request))
        access_token, user_id, url_state = flow.finish(request.GET)
        log.info("Success response from Dropbox.")
        # Not storing in DB, until this app is to be used multiple user.
        return Response("heroku config:set TOKEN=%s" % access_token)
def dropboxauth_url(request):
    url = request.application_url + '/dropboxauth'
    # Dropbox needs https.
    if 'https' not in url:
        url = url.replace('http', 'https')

@view_config(name='incoming', request_method='POST')
def incoming(request):
    message = PostmarkInbound(json=request.body)
    handle_email(message)
    return Response("Ok")


# HTTP configuration
# ------------------

def configure_webapp():
    session_secret = os.getenv("SESSION_SECRET")
    if session_secret is None:
        raise ValueError("session secret not set")

    config = Configurator()
    config.scan()
    session_factory = SignedCookieSessionFactory(session_secret)
    config.set_session_factory(session_factory)

    app = config.make_wsgi_app()

    # FIXME: only seeing error and above.
    h = logging.StreamHandler()
    h.setLevel(logging.DEBUG)
    log.addHandler(h)

    return app


# Dropbox configuration, utility
# ------------------------------

def configure_dropbox():
    app_key = os.getenv("DROPBOX_APP_KEY")
    app_secret = os.getenv("DROPBOX_APP_SECRET")
    if app_key is None or app_secret is None:
        raise ValueError("DROPBOX env vars not set")
    return app_key, app_secret

def make_dropbox_auth_flow(session, redirect_url):
    app_key, app_secret = configure_dropbox()
    flow = DropboxOAuth2Flow(app_key, app_secret, redirect_url,
                             session, "dropbox-auth-csrf-token")
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

def get_dropbox_token():
    token = os.getenv("TOKEN")
    if token is None:
        raise ValueError("TOKEN not set (user did not initiate oauth?)")
    return token

def dropbox_write(path, content, overwrite=False):
    client = DropboxClient(get_dropbox_token())
    info = client.put_file(path, content, overwrite=overwrite)
    log.error("Created file %s with metadata %s", path, info)

def dropbox_append(path, content):
    client = DropboxClient(get_dropbox_token())
    existing_content = ''
    try:
        with client.get_file(path) as f:
            existing_content = f.read()
    except dropbox.rest.ErrorResponse as err:
        if err.status == 404:
            existing_content = ''
        else:
            raise
    dropbox_write(path, existing_content + content, overwrite=True)



# main
# ----

configure_dropbox()
app = configure_webapp()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    server = make_server('0.0.0.0', port, app)
    log.error("Running Pyramid at http://0.0.0.0:$PORT")
    server.serve_forever()
