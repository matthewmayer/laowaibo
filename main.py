#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import datetime
import httplib
import sys
import logging
import oauth
import random
import time
from apiclient.discovery import build
import os
import hashlib

from weibopy.api import API
from weibopy.auth import OAuthHandler
from google.appengine.ext import webapp
from google.appengine.api import memcache
from google.appengine.ext.webapp import util
from google.appengine.api import memcache

from abstract import BaseHandler

# fake urls for the test server (matches ones in server.py)
SERVER = 'api.t.sina.com.cn'
ACCESS_TOKEN_URL = 'http://'+SERVER+'/oauth/access_token'
AUTHORIZATION_URL = 'http://'+SERVER+'/oauth/authorize'
CALLBACK_URL = os.environ['HTTP_HOST']
CONSUMER_KEY = '811259784'
CONSUMER_SECRET = 'bb501362af3d370773d5dba442cf773e'
PORT = 80
REQUEST_TOKEN_URL = 'http://'+SERVER+'/oauth/request_token'
RESOURCE_URL = os.environ['HTTP_HOST']
PAGE_SIZE=10

# Set cookie. Expiration is 2 days long.
expires = datetime.datetime.now() + datetime.timedelta(days=2)
expires_rfc822 = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
cookie = "; expires=%s; path=/" % expires_rfc822

class SimpleOAuthClient(oauth.OAuthClient):
    def __init__(self, server, port=httplib.HTTP_PORT, request_token_url='',
                 access_token_url='', authorization_url=''):
        self.server = server
        self.port = port
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorization_url = authorization_url
        self.connection = httplib.HTTPConnection("%s:%d" % (self.server, 
                                                            self.port))

    def fetch_request_token(self, oauth_request):
        # via headers
        # -> OAuthToken
        self.connection.request(oauth_request.http_method,
                                self.request_token_url,
                                headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        return oauth.OAuthToken.from_string(response.read())

    def fetch_access_token(self, oauth_request):
        # via headers
        # -> OAuthToken
        self.connection.request(oauth_request.http_method,
                                self.access_token_url,
                                headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        return oauth.OAuthToken.from_string(response.read())

    def authorize_token(self, oauth_request):
        # via url
        # -> typically just some okay response
        self.connection.request(oauth_request.http_method,
                                oauth_request.to_url()) 
        response = self.connection.getresponse()
        return response.read()


class SinaOauthPhaseOne(webapp.RequestHandler):
    def get(self):
        # setup/initial
        client = SimpleOAuthClient(SERVER, PORT, REQUEST_TOKEN_URL,
                                   ACCESS_TOKEN_URL, AUTHORIZATION_URL)
        consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
        signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()
        signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()

        # get request token
        # print '* Obtain a request token ...'
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(
                            consumer,
                            callback=CALLBACK_URL,
                            http_url=client.request_token_url)
        oauth_request.sign_request(signature_method_plaintext, consumer, None)
    
        #print 'REQUEST (via headers)'
        #print 'parameters: %s' % str(oauth_request.parameters)
        cid = str(int(random.uniform(0,sys.maxint)))
        token = client.fetch_request_token(oauth_request)
        memcache.set("PK_"+cid, token.to_string())
        PHASETWO_CALLBACK_URL = 'http://'+os.environ['HTTP_HOST']+'/oauth_authorized?id=' + cid

        #print '* Authorize the request token ...'
        oauth_request = oauth.OAuthRequest.from_token_and_callback(
                            token=token,
                            callback=PHASETWO_CALLBACK_URL,
                            http_url=client.authorization_url)
        #??? response = client.authorize_token(oauth_request)
        #??? self.redirect(response)
        # OR USING BELOW LINES instead ?
        oauth_request.sign_request(signature_method_hmac_sha1, consumer, token)
        self.redirect(oauth_request.to_url())
        
        
class SinaOauthPhaseTwo(webapp.RequestHandler):
    # get access token
    def get(self):
        verifier = self.request.get('oauth_verifier')
        logging.info('verify id = %s' % verifier)
        
        signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()
        
        # Get token - key and secret from memcache that we set on SinaOauthPhaseOne
        tokenstr = memcache.get("PK_"+self.request.get('id'))
        memcache.delete("PK_"+self.request.get('id'))
        token = oauth.OAuthToken.from_string(tokenstr)                
               
        consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
        client = SimpleOAuthClient(SERVER, PORT, REQUEST_TOKEN_URL,
                                   ACCESS_TOKEN_URL, AUTHORIZATION_URL)
        
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(
                            consumer,
                            token=token, verifier=verifier,
                            http_url=client.access_token_url)
        oauth_request.sign_request(signature_method_hmac_sha1, consumer, token)
        
        # Finally get access_token after verifier is matched.
        access_token = client.fetch_access_token(oauth_request)
        logging.info('Sina Authorized access_token = %s' % access_token)
        
        # Set cookie into browser in case for further use.
        self.response.headers.add_header('Set-Cookie',
                                         'oauth_key=' + access_token.key + cookie)
        self.response.headers.add_header('Set-Cookie',
                                         'oauth_secret=' + access_token.secret + cookie)
        
        # Call Sina weibopy API auth.OAuthHandler() and set access_token to
        # fetch access_resource aka:user resource.
        auth_access_resource = OAuthHandler(
                                    consumer_key=CONSUMER_KEY,
                                    consumer_secret=CONSUMER_SECRET)
        auth_access_resource.set_access_token(access_token.key,
                                              access_token.secret)
        
        # API() inherits auth_access_resource return.
        api = API(auth_access_resource)
        
        # I call api.verify_credentials instead of use auth.OAuthHandler.get_username
        username = api.verify_credentials()
 
        if username:
            self.username = username.screen_name
            self.response.headers.add_header('Set-Cookie',
                                             'sina_username=' + self.username + cookie)
            logging.info('Sina username: %s' % self.username)
        else:
            logging.info('NO SINA USER')

        
        self.redirect('/')


class LogoutHandler(webapp.RequestHandler):
    def get(self):
        expires_rfc822 = time.time() - 86400
        cookie = "; expires=%s; path=/" % expires_rfc822
        self.response.headers.add_header('Set-Cookie',
                                         'sina_username=' + "" + cookie)
        self.redirect("/")

class Translator(object):
    @classmethod
    def translate(clz,text,source='zh',target='en'):
        ahash = hashlib.sha224(text.encode('utf-8')).hexdigest()
        trans = memcache.get(ahash)
        if trans is None:
            logging.info('MISS %s',ahash)
            service = build('translate', 'v2',
                        developerKey='AIzaSyDBy_hjgHTqJhILOrlTfb_3rTYYgM6Pypc')
            data = (service.translations().list(
                  source=source,
                  target=target,
                  q=[text]
                ).execute())
            trans = data['translations'][0]['translatedText']
            memcache.add(ahash,trans,60*60*24*7)
        else:
            logging.info('HIT %s',ahash)
        return trans

class TranslateHandler(BaseHandler):
    def post(self):
        text = self.request.get('text')
        source,target = self.request.get('lang').split("|")
        self.response.out.write(Translator.translate(text,source=source,target=target))

class MainPage(BaseHandler): 
    def get(self):
        # Check Sina user logged in or not.
        sina_username =  self.request.cookies.get("sina_username")
        if sina_username:
            oauth_key = self.request.cookies.get("oauth_key")
            oauth_secret = self.request.cookies.get("oauth_secret")
            auth = OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
            auth.setToken(oauth_key, oauth_secret)
            api = API(auth)
            view = self.request.get('view')
            timeline = None
            if view=='mine':
                timeline = api.user_timeline(count=PAGE_SIZE, page=1)
            elif view=='mentions':
                timeline = api.mentions(count=PAGE_SIZE, page=1)
            else:
                timeline = api.friends_timeline(count=PAGE_SIZE, page=1)
            for status in timeline:
                status.text_en = Translator.translate(status.text)
                status.created_at_iso = "%s+0800" % (str(status.created_at).replace(" ","T"))
                if hasattr(status,'retweeted_status'):
                    status.retweeted_text_en = Translator.translate(status.retweeted_status.text)
            self.render_template("index.html",{"timeline":timeline,"username":sina_username})
        else:
            self.response.out.write("<a href='/oauth/sina_login'>Login with Sina</a>")

class ComposeHandler(BaseHandler):
    def get(self):
        # Check Sina user logged in or not.
        self.render_template("compose.html",{})
def main():
    application = webapp.WSGIApplication(
                                         [('/', MainPage),
                                          ('/oauth/sina_login', SinaOauthPhaseOne),
                                          ('/oauth_authorized', SinaOauthPhaseTwo),
                                          ('/oauth/sina_logout', LogoutHandler),
                                          ('/translate',TranslateHandler),
                                          ('/compose',ComposeHandler)
                                          
                                          ],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
