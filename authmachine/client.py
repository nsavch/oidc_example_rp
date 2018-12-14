import base64
import hashlib
import json
from typing import Dict, List
from urllib.parse import urlencode

import os
import requests
from Crypto import Random
from Crypto.Cipher import AES
from django.conf import settings
from django.urls import reverse
from oic import rndstr
from oic.oauth2 import AuthorizationResponse
from oic.oic import Client
from oic.oic.message import OpenIDSchema, AccessTokenResponse
from oic.utils.authn.client import ClientSecretBasic, ClientSecretPost


class AESCipher(object):
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw).encode()
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class AuthMachineClient(object):
    def __init__(self, request):
        self.request = request
        self.client = self.get_client()
        if request.is_secure():
            proto = 'https://'
        else:
            proto = 'http://'
        self.host = proto + request.get_host()

    def get_client(self):
        client = Client(client_authn_method={
            'client_secret_post': ClientSecretPost,
            'client_secret_basic': ClientSecretBasic
        })
        client.provider_config(settings.AUTHMACHINE_URL)
        client.client_id = settings.AUTHMACHINE_CLIENT_ID
        client.client_secret = settings.AUTHMACHINE_CLIENT_SECRET
        client.verify_ssl = True
        return client

    def get_authorization_url(self, request, next=None):
        state = json.dumps({'next': next}) if next else {}
        request.session['state'] = state

        aes_cipher = AESCipher(settings.AUTHMACHINE_STATE_ENCRYPTION_KEY)

        nonce = rndstr()

        args = {
            'client_id': self.client.client_id,
            'response_type': 'code',
            'scope': settings.AUTHMACHINE_SCOPE,
            'nonce': nonce,
            'redirect_uri': self.host + reverse('authmachine:sso-callback'),
            'state': aes_cipher.encrypt(state)
        }
        url = self.client.provider_info['authorization_endpoint'] + '?' + urlencode(args, True)
        return url

    def get_access_token(self, aresp):
        """Gets access token from AuthMachine.
        Args:
            aresp (AuthorizationResponse):
        """
        args = {
            'code': aresp['code'],
            'client_id': self.client.client_id,
            'client_secret': self.client.client_secret,
            'redirect_uri': self.host + reverse('authmachine:sso-callback')
        }

        response = self.client.do_access_token_request(
            scope=settings.AUTHMACHINE_SCOPE,
            state=aresp['state'],
            request_args=args,
            authn_method='client_secret_post')

        assert isinstance(response, AccessTokenResponse), \
            'Response of type {} observed. Expecting AccessTokenResponse instead.'

    def get_state(self, request, aresp):
        aes_cipher = AESCipher(settings.AUTHMACHINE_STATE_ENCRYPTION_KEY)
        decrypted_state = aes_cipher.decrypt(aresp['state'])

        assert decrypted_state == request.session['state'], \
            'State came from AuthMachine does not match to state from session.'
        return json.loads(decrypted_state)

    def get_userinfo(self, authorization_response):
        """Returns Open ID userinfo as dict.
        """

        self.get_access_token(authorization_response)
        user_info = self.client.do_user_info_request(
            state=authorization_response['state'],
            authn_method='client_secret_post')

        assert isinstance(user_info, OpenIDSchema)
        return user_info.to_dict()

    def get_authorization_response(self, request):
        authorization_response = self.client.parse_response(
            AuthorizationResponse,
            info=request.GET,
            sformat='dict')
        return authorization_response

    def do_api_request(self, method, url, payload=None, query_params=None, **kwargs):
        absolute_url = os.path.join(settings.AUTHMACHINE_URL, url)

        if payload:
            kwargs['data'] = json.dumps(payload, sort_keys=True)

        if query_params:
            absolute_url += '?' + urlencode(query_params, doseq=True)

        headers = kwargs.pop('headers', {})
        headers['Content-Type'] = 'application/json'
        headers['Authorization'] = 'Token %s' % settings.AUTHMACHINE_API_TOKEN
        response = requests.request(method=method, url=absolute_url, headers=headers, **kwargs)

        return response

    def get_permissions(self, user_id: str) -> List[str]:
        tenant = self.request.tenant
        response = self.do_api_request('get', 'api/scim/v1/Users/{}/permissions'.format(user_id),
                                       query_params={'object': [tenant.name]})
        print(tenant.name)
        if response.status_code == 200:
            data = response.json()
            print(data)
            return data[tenant.name]
        else:
            return []
