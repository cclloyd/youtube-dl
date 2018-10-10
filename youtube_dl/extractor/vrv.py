# coding: utf-8
from __future__ import unicode_literals

import base64
import json
import hashlib
import hmac
import random
import string
import time
from pprint import pprint

from .common import InfoExtractor
from ..compat import (
    compat_urllib_parse_urlencode,
    compat_urllib_parse,
)
from ..utils import (
    float_or_none,
    int_or_none,
)


class VRVBaseIE(InfoExtractor):
    _API_DOMAIN = None
    _API_PARAMS = {}
    _OAUTH_PARAMS = {}
    _OAUTH_TOKEN = ''
    _OAUTH_REFRESH = ''
    _CMS_POLICY = {}
    _CMS_SIGNING = {}
    oauthsig = ''
    _LOGIN_URL = 'https://vrv.co/signin'
    oauth_token = None
    oauth_signature = ''

    def _call_api(self, path, video_id, note, data=None, headers=None, token=None, use_policy=False):
        base_url = self._API_DOMAIN + '/core/' + path
        query_params = {
            'oauth_consumer_key': self._API_PARAMS['oAuthKey'],
            'oauth_nonce': ''.join([random.choice(string.ascii_letters) for _ in range(32)]),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': int(time.time()),
            'oauth_version': '1.0',
        }
        encoded_query = compat_urllib_parse_urlencode(query_params)

        if self._OAUTH_TOKEN:
            encoded_query += '&oauth_token=' + compat_urllib_parse.quote(self._OAUTH_TOKEN, '')

        if not headers:
            headers = self.geo_verification_headers()

        auth_header = 'OAuth oauth_consumer_key="%s", ' \
                      'oauth_nonce="%s", ' \
                      'oauth_signature="%s", ' \
                      'oauth_signature_method="%s", ' \
                      'oauth_timestamp="%s", ' \
                      'oauth_token="%s", ' \
                      'oauth_version="%s"'

        if data:
            data = json.dumps(data).encode()
            headers['Content-Type'] = 'application/json'
        method = 'POST' if data else 'GET'
        base_string = '&'.join([method, compat_urllib_parse.quote(base_url, ''), compat_urllib_parse.quote(encoded_query, '')])
        if self.oauth_signature:
            oauth_signature = base64.b64encode(hmac.new(
                (self._API_PARAMS['oAuthSecret'] + '&').encode('ascii'),
                base_string.encode(), hashlib.sha1).digest()).decode()
        else:
            oauth_signature = base64.b64encode(hmac.new(
                (self._API_PARAMS['oAuthSecret'] + '&').encode('ascii'),
                base_string.encode(), hashlib.sha1).digest()).decode()
            #oauth_signature = self.oauth_signature
        encoded_query += '&oauth_signature=' + compat_urllib_parse.quote(oauth_signature, '')
        if self._OAUTH_TOKEN:
            oauth_signature = base64.b64encode(hmac.new(
                #(self._OAUTH_PARAMS['oauth_token_secret'] + '&').encode('ascii'),
                (self._API_PARAMS['oAuthSecret'] + '&').encode('ascii'),
                base_string.encode(), hashlib.sha1).digest()).decode()
            headers['authorization'] = auth_header % (
                query_params['oauth_consumer_key'],
                query_params['oauth_nonce'],
                oauth_signature,
                query_params['oauth_signature_method'],
                query_params['oauth_timestamp'],
                self._OAUTH_TOKEN,
                query_params['oauth_version'],
            )
        print(headers)
        return self._download_json(
            '?'.join([base_url, encoded_query]), video_id,
            note='Downloading %s JSON metadata' % note, headers=headers, data=data)

    def _call_cms(self, path, video_id, note):
        if not self._CMS_SIGNING:
            print("RESIGNING CMS")
            self._CMS_SIGNING = self._call_api('index', video_id, 'CMS Signing')['cms_signing']
        headers = self.geo_verification_headers()
        return self._download_json(
            self._API_DOMAIN + path, video_id, query=self._CMS_SIGNING,
            note='Downloading %s JSON metadata' % note, headers=headers)

    def _set_api_params(self, webpage, video_id):
        if not self._API_PARAMS:
            self._API_PARAMS = self._parse_json(self._search_regex(
                r'window\.__APP_CONFIG__\s*=\s*({.+?})</script>',
                webpage, 'api config'), video_id)['cxApiParams']
            self._API_DOMAIN = self._API_PARAMS.get('apiDomain', 'https://api.vrv.co')
        self._API_PARAMS = self._parse_json(self._search_regex(
            r'window\.__APP_CONFIG__\s*=\s*({.+?})</script>',
            webpage, 'api config'), video_id)['cxApiParams']
        self._API_DOMAIN = self._API_PARAMS.get('apiDomain', 'https://api.vrv.co')

    def _get_cms_resource(self, resource_key, video_id):
        return self._call_api(
            'cms_resource', video_id, 'resource path', data={
                'resource_key': resource_key,
            })['__links__']['cms_resource']['href']

    def _login(self, video_id):
        username, password = self._get_login_info()
        data = {
            'email': username,
            'password': password,
        }
        self._OAUTH_PARAMS = self._call_api('authenticate/by:credentials', video_id, note='login', data=data)
        if self._OAUTH_PARAMS:
            self._OAUTH_TOKEN = self._OAUTH_PARAMS['oauth_token']
            self._CMS_SIGNING = {}


class VRVIE(VRVBaseIE):
    IE_NAME = 'vrv'
    _VALID_URL = r'https?://(?:www\.)?vrv\.co/watch/(?P<id>[A-Z0-9]+)'
    _TESTS = [{
        'url': 'https://vrv.co/watch/GR9PNZ396/Hidden-America-with-Jonah-Ray:BOSTON-WHERE-THE-PAST-IS-THE-PRESENT',
        'info_dict': {
            'id': 'GR9PNZ396',
            'ext': 'mp4',
            'title': 'BOSTON: WHERE THE PAST IS THE PRESENT',
            'description': 'md5:4ec8844ac262ca2df9e67c0983c6b83f',
            'uploader_id': 'seeso',
        },
        'params': {
            # m3u8 download
            'skip_download': True,
        },
    }]

    def _extract_vrv_formats(self, url, video_id, stream_format, audio_lang, hardsub_lang):
        if not url or stream_format not in ('hls', 'dash'):
            return []
        assert audio_lang or hardsub_lang
        stream_id_list = []
        if audio_lang:
            stream_id_list.append('audio-%s' % audio_lang)
        if hardsub_lang:
            stream_id_list.append('hardsub-%s' % hardsub_lang)
        stream_id = '-'.join(stream_id_list)
        format_id = '%s-%s' % (stream_format, stream_id)
        if stream_format == 'hls':
            adaptive_formats = self._extract_m3u8_formats(
                url, video_id, 'mp4', m3u8_id=format_id,
                note='Downloading %s m3u8 information' % stream_id,
                fatal=False)
        elif stream_format == 'dash':
            adaptive_formats = self._extract_mpd_formats(
                url, video_id, mpd_id=format_id,
                note='Downloading %s MPD information' % stream_id,
                fatal=False)
        if audio_lang:
            for f in adaptive_formats:
                if f.get('acodec') != 'none':
                    f['language'] = audio_lang
        return adaptive_formats

    def _real_extract(self, url):
        video_id = self._match_id(url)
        webpage = self._download_webpage(
            url, video_id,
            headers=self.geo_verification_headers())
        media_resource = self._parse_json(self._search_regex(
            r'window\.__INITIAL_STATE__\s*=\s*({.+?})</script>',
            webpage, 'inital state'), video_id).get('watch', {}).get('mediaResource') or {}

        video_data = media_resource.get('json')
        if not video_data:
            self._set_api_params(webpage, video_id)
            episode_path = self._get_cms_resource(
                'cms:/episodes/' + video_id, video_id)
            video_data = self._call_cms(episode_path, video_id, 'video')
        title = video_data['title']

        streams_json = media_resource.get('streams', {}).get('json', {})
        if not streams_json:
            self._set_api_params(webpage, video_id)
            self._login(video_id)
            auth_header = 'OAuth oauth_consumer_key="%s", ' \
                          'oauth_nonce="%s", ' \
                          'oauth_signature="%s", ' \
                          'oauth_signature_method="%s", ' \
                          'oauth_timestamp="%s", ' \
                          'oauth_token="%s", ' \
                          'oauth_version="%s"'
            base_url = self._API_DOMAIN + '/core/' + video_data['__href__']
            query_params = {
                'oauth_consumer_key': self._API_PARAMS['oAuthKey'],
                'oauth_nonce': ''.join([random.choice(string.ascii_letters) for _ in range(32)]),
                'oauth_signature_method': 'HMAC-SHA1',
                'oauth_timestamp': int(time.time()),
                'oauth_version': '1.0',
            }
            encoded_query = compat_urllib_parse_urlencode(query_params)

            #streams_url = self._call_api('accounts/1480947/premium_access', video_id, note='streams')
            base_string = '&'.join(['GET', compat_urllib_parse.quote(base_url, ''), compat_urllib_parse.quote(encoded_query, '')])

            headers=self.geo_verification_headers()
            oauth_signature = base64.b64encode(
                hmac.new(
                    (self._API_PARAMS['oAuthSecret'] + '&').encode('ascii'), base_string.encode(), hashlib.sha1
                    #(self._OAUTH_PARAMS['oauth_token_secret'] + '&').encode('ascii'),base_string.encode(), hashlib.sha1
                ).digest()
            ).decode()
            headers['authorization'] = auth_header % (
                query_params['oauth_consumer_key'],
                query_params['oauth_nonce'],
                oauth_signature,
                query_params['oauth_signature_method'],
                query_params['oauth_timestamp'],
                self._OAUTH_TOKEN,
                query_params['oauth_version'],
            )


            webpage = self._download_webpage(
                url, video_id,
                headers=headers)
            media_resource = self._parse_json(self._search_regex(
                r'window\.__INITIAL_STATE__\s*=\s*({.+?})</script>',
                webpage, 'inital state'), video_id).get('watch', {}).get('mediaResource') or {}

            video_data = media_resource.get('json')

            streams_url = self._call_cms(video_data['__href__'], video_id, note='streams')
            #self._set_api_params(webpage, video_id)
            #episode_path = self._get_cms_resource(
            #    'cms:/episodes/' + video_id, video_id)
            #video_data = self._call_cms(episode_path, video_id, 'video')
            pprint(streams_url)

            exit("FUCK")



            headers = self.geo_verification_headers()
            auth_header = 'OAuth oauth_consumer_key="%s", ' \
                          'oauth_nonce="%s", ' \
                          'oauth_signature="%s", ' \
                          'oauth_signature_method="%s", ' \
                          'oauth_timestamp="%s", ' \
                          'oauth_token="%s", ' \
                          'oauth_version="%s"'

            encoded_query = compat_urllib_parse_urlencode({
                'oauth_consumer_key': self._API_PARAMS['oAuthKey'],
                'oauth_nonce': ''.join([random.choice(string.ascii_letters) for _ in range(32)]),
                'oauth_signature_method': 'HMAC-SHA1',
                'oauth_timestamp': int(time.time()),
                'oauth_version': '1.0',
            })
            base_string = '&'.join(['GET', compat_urllib_parse.quote(url, ''), compat_urllib_parse.quote(encoded_query, '')])
            oauth_signature = base64.b64encode(hmac.new(
                (self._API_PARAMS['oAuthSecret'] + '&').encode('ascii'),
                base_string.encode(), hashlib.sha1).digest()).decode()
            encoded_query += '&oauth_signature=' + compat_urllib_parse.quote(oauth_signature, '')
            encoded_query += '&oauth_token=' + compat_urllib_parse.quote(self.oauth_token, '')

            headers['Authorization'] = auth_header % (
                self._API_PARAMS['oAuthKey'],
                ''.join([random.choice(string.ascii_letters) for _ in range(32)]),
                oauth_signature,
                'HMAC-SHA1',
                int(time.time()),
                self.oauth_token,
                '1.0',
            )
            print('?'.join([url, encoded_query]))
            exit()

            webpage = self._download_webpage(
                '?'.join([url, encoded_query]), video_id,
                headers=headers)
            media_resource = self._parse_json(self._search_regex(
                r'window\.__INITIAL_STATE__\s*=\s*({.+?})</script>',
                webpage, 'inital state'), video_id).get('watch', {}).get('mediaResource') or {}

            video_data = media_resource.get('json')

            pprint(video_data)

            exit(0)

            auth_header = 'OAuth oauth_consumer_key="%s", ' \
                          'oauth_nonce="%s", ' \
                          'oauth_signature="%s", ' \
                          'oauth_signature_method="%s", ' \
                          'oauth_timestamp="%s", ' \
                          'oauth_token="%s", ' \
                          'oauth_version="%s"'

            data = {
                'email': 'luircin@gmail.com',
                'password': 'Zekiuwashere',
            }
            login_url = '%s/core/authenticate/by:credentials' % self._API_DOMAIN

            base_url = login_url
            encoded_query = compat_urllib_parse_urlencode({
                'oauth_consumer_key': self._API_PARAMS['oAuthKey'],
                'oauth_nonce': ''.join([random.choice(string.ascii_letters) for _ in range(32)]),
                'oauth_signature_method': 'HMAC-SHA1',
                'oauth_timestamp': int(time.time()),
                'oauth_version': '1.0',
            })
            headers = self.geo_verification_headers()

            data = json.dumps(data).encode()
            headers['Content-Type'] = 'application/json'
            base_string = '&'.join(
                ['POST', compat_urllib_parse.quote(base_url, ''), compat_urllib_parse.quote(encoded_query, '')])
            oauth_signature = base64.b64encode(hmac.new(
                (self._API_PARAMS['oAuthSecret'] + '&').encode('ascii'),
                base_string.encode(), hashlib.sha1).digest()).decode()
            encoded_query += '&oauth_signature=' + compat_urllib_parse.quote(oauth_signature, '')

            print(login_url)
            response_login = requests.post(login_url + '?' + encoded_query, data)
            pprint(response_login.json())
            self.oauth_token = response_login.json()['oauth_token']

            #self._set_api_params(webpage, video_id)
            #episode_path = self._get_cms_resource(
            #    'cms:/episodes/' + video_id, video_id)
            #video_data = self._call_cms(episode_path, video_id, 'video')
            pprint(video_data)
            exit(0)





            #video_url = self._get_cms_resource('cms:/episodes/G6P8Z9VV6', video_id)
            #print("video_url: %s" % (self._API_DOMAIN + video_url))
            #pprint(self._call_cms(video_url, video_id, note='video info'))

            headers = self.geo_verification_headers()
            oauth_token = response_login.json()['oauth_token']
            headers['Authorization'] = auth_header % (
                self._API_PARAMS['oAuthKey'],
                ''.join([random.choice(string.ascii_letters) for _ in range(32)]),
                oauth_signature,
                'HMAC-SHA1',
                int(time.time()),
                oauth_token,
                '1.0',
            )

            #video_info = self._download_json(
            #    self._API_DOMAIN + video_url, video_id, query=self._CMS_SIGNING,
            #    note='Downloading video info JSON metadata', headers=headers)
            #print(video_info)








            exit(0)




            #pprint(video_data)
            video_url = '%s/core%s' % (self._API_DOMAIN, self._get_cms_resource('cms:/episodes/G6P8Z9VV6', video_id))


            base_url = video_url
            base_string = '&'.join(
                ['GET', compat_urllib_parse.quote(base_url, ''), compat_urllib_parse.quote(encoded_query, '')])
            oauth_signature = base64.b64encode(hmac.new(
                (self._API_PARAMS['oAuthSecret'] + '&').encode('ascii'),
                base_string.encode(), hashlib.sha1).digest()).decode()
            encoded_query += '&oauth_signature=' + compat_urllib_parse.quote(oauth_signature, '')

            #pprint(video_url + '?' + encoded_query)
            #exit(0)
            video_url = video_url.replace('-', networks)
            response_video = requests.get(video_url + '?' + encoded_query)
            pprint(response_video.json())





            exit("login end")










            policy_url = "index"
            policy_info = self._call_api(policy_url, video_id, 'policy', use_policy=False)
            pprint(policy_info['cms_signing'])
            self._CMS_POLICY = policy_info['cms_signing']
            exit(0)

            pprint(media_resource)
            episode_url = media_resource['json']['__href__']
            info = self._call_api(episode_url, video_id, 'info')
            pprint(info)
            exit(0)

            #pprint(policy_info)
            #policy = policy_info['Policy']
            #exit(0)
            #"/cms/v2/US/M3/alpha,cartoonhangover,crunchyroll,curiositystream,dramafever,fandor,funimation,geekandsundry,mondo,mubi,nerdist,roosterteeth,shudder,tested,vrvselect/episodes/G6K5ZM4GY"
            path = "https://api.vrv.co/cms/v2/US/M3/-/videos/GR0XDMJGY/streams?Policy=%s&Signature=%s&Key-Pair-Id=%s" % (self._CMS_POLICY['Policy'], self._CMS_POLICY['Signature'], self._CMS_POLICY['Key-Pair-Id'])
            info = self._call_api(path, video_id, 'test')

            exit(0)

            video_data = media_resource.get('json')
            if not video_data:
                self._set_api_params(webpage, video_id)
                episode_path = self._get_cms_resource(
                    'cms:/episodes/' + video_id, video_id)
                video_data = self._call_cms(episode_path, video_id, 'video')
            title = video_data['title']

            streams_json = media_resource.get('streams', {}).get('json', {})
            if not streams_json:
                pprint(video_data)
                exit("STILL NO STREAMS")
                streams_path = video_data['__links__']['streams']['href']
                streams_json = self._call_cms(streams_path, video_id, 'streams')
            else:
                print("HAVE STREAMS")




            exit("END OF NEW TEST")


            base_url = login_url #self._API_DOMAIN + '/core/' + path
            encoded_query = compat_urllib_parse_urlencode({
                'oauth_consumer_key': self._API_PARAMS['oAuthKey'],
                'oauth_nonce': ''.join([random.choice(string.ascii_letters) for _ in range(32)]),
                'oauth_signature_method': 'HMAC-SHA1',
                'oauth_timestamp': int(time.time()),
                'oauth_version': '1.0',
            })

            authorization_header = 'OAuth oauth_consumer_key="%s", oauth_nonce="%s", oauth_signature="%s", oauth_signature_method="%s", oauth_timestamp="%s", oauth_token="%s", oauth_version="%s"'
            headers = self.geo_verification_headers()
            if data:
                data = json.dumps(data).encode()
                headers['Content-Type'] = 'application/json'
            method = 'POST' if data else 'GET'
            base_string = '&'.join(
                [method, compat_urllib_parse.quote(base_url, ''), compat_urllib_parse.quote(encoded_query, '')])
            oauth_signature = base64.b64encode(hmac.new(
                (self._API_PARAMS['oAuthSecret'] + '&').encode('ascii'),
                base_string.encode(), hashlib.sha1).digest()).decode()
            encoded_query += '&oauth_signature=' + compat_urllib_parse.quote(oauth_signature, '')
            print(oauth_signature)
            #exit(0)

            #base_string = login_url
            #oauth_signature = base64.b64encode(hmac.new(self._API_PARAMS['oAuthSecret'].encode('ascii'), base_string.encode(), hashlib.sha1).digest()).decode()

            encoded_query = 'OAuth ' \
                            'oauth_consumer_key="%s", ' \
                            'oauth_nonce="%s", ' \
                            'oauth_signature="%s", ' \
                            'oauth_signature_method="HMAC-SHA1", ' \
                            'oauth_timestamp="%s", ' \
                            'oauth_version="1.0"' \
                            % (
                                self._API_PARAMS['oAuthKey'],
                                ''.join([random.choice(string.ascii_letters) for _ in range(32)]),
                                oauth_signature,
                                int(time.time())
                            )
            print(encoded_query)
            #exit("ENCODED QUERY")

            headers = {'authorization': encoded_query}
            #r = requests.get(login_url)
            pprint(r.json())
            exit("END OF NEW METHOD")
            #streams_path = video_data['__links__']['streams']['href']
            #streams_path = "cms/v2/US/M3/-/videos/%s/streams" % video_id
            #streams_json = json.loads('{"__class__":"video_streams","__href__":"/cms/v2/US/M3/alpha,cartoonhangover,crunchyroll,curiositystream,dramafever,fandor,funimation,geekandsundry,mondo,mubi,nerdist,roosterteeth,shudder,tested,vrvselect/videos/GR0XDMJGY/streams","__resource_key__":"cms:/videos/GR0XDMJGY/streams","__links__":{"resource":{"href":"/cms/v2/US/M3/alpha,cartoonhangover,crunchyroll,curiositystream,dramafever,fandor,funimation,geekandsundry,mondo,mubi,nerdist,roosterteeth,shudder,tested,vrvselect/episodes/G6K5ZM4GY"}},"__actions__":{},"media_id":"GR0XDMJGY","audio_locale":"en-US","subtitles":{"en-US":{"locale":"en-US","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_timed_text_subtitle_en-US.ssa?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiX3RpbWVkX3RleHRfc3VidGl0bGVfKi5zc2EiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE1Mzg5ODg2NTB9fX1dfQ__\u0026Signature=FnQ12UsuSWlRI5oZhOQ77Ose71jSRJY3sCYtVZ0aDGWMQ2l-KwPeQUgSSxay9A5rKeDVN533DGHT27vtY-RfRQlh98P2y80wIUvoU82NjdU-KQ6jye2BY2NFx0TSn7XuwLAlYhuFt~OSxY46qnWAw08aK9~5wOkZZvIm13jzzgWycaOW1gi5XE~ItApunxgg9uNpADpPFMTjUy~NWaX7Z9jB9zMOKRHodMUlV8J8Qq0K4SMCAHi-PTzkxhYAwQHyRWeTOvtamg57gO3Hrx2SJP9pmpwkNl~zovbXRd9rpMalBK-dz7GF2hv1hfs9YJ9jkMD14tu68yqB11N~-5WJJg__\u0026Key-Pair-Id=DLVR","format":"ssa"}},"captions":{"en-US":{"locale":"en-US","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_timed_text_caption_en-US.scc?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiX3RpbWVkX3RleHRfY2FwdGlvbl8qLnNjYyIsIkNvbmRpdGlvbiI6eyJEYXRlTGVzc1RoYW4iOnsiQVdTOkVwb2NoVGltZSI6MTUzODk4ODY1MH19fV19\u0026Signature=X3Rtm-5fcXR9KABjylnfVo49n67FCJnvE0HGUpWpX2Aj4a6BpLsXlI~MLpqFtVWt8uo-aHTZaJT3qyte6zfSxYyVMZpB6IxOgEV6~y7CW2mcTFwbr-1GrW-IezgP3ifuZyQMR9OMXtG87WtrIOFd0T4IyVv5QkXaEMRTFie7PpHXlDaC0~Gf6a7NTh0guFwlfpHjJKkvpq2oTWVTWo22N0IvoO4DoeSLe7IUX50hih1UcfkrxWyB2eog9mI5D5fioFv0xFKqI4Ttt7-cGIo9gBJJ20qYer7H5Wx1e0lgC0JeR7fiVqKeQTx1PzPNat0unQRfHiUODdq1FqQk2rcVRg__\u0026Key-Pair-Id=DLVR","format":"scc"}},"streams":{"adaptive_dash":{"":{"hardsub_locale":"","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_,2232668_720.mp4,2232668_1080.mp4,2232668_480.mp4,2232668_360.mp4,.urlset/manifest.mpd?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiXywyMjMyNjY4XzcyMC5tcDQsMjIzMjY2OF8xMDgwLm1wNCwyMjMyNjY4XzQ4MC5tcDQsMjIzMjY2OF8zNjAubXA0LC51cmxzZXQvbWFuaWZlc3QubXBkIiwiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6eyJBV1M6RXBvY2hUaW1lIjoxNTM4OTg4NjUwfX19XX0_\u0026Signature=f03IL7lVjzdjloV3oqGdWKUYCvY~M39jY~n9sDsZylt2zrD9WRYeV4uK0f857xnSdxg57y1RGE08k2kr1YkZs2Bsh8Y~Vm-QtsaiXk1pHmS5OvkkQ6toaLBHd4pAI874y5qXqUiu5dXkv-ysKvwJGCj4N8rT7LqvC6z9mb8-fwH4bco0vpgukDGHt2SH0GZeqF~7QaAzN3y95yvQUbqoVjOLY14SA9qVsjxRl68uVgbW2IHtftLoC191Wv~bqX3Iz3jkdiliqXDuCJ3nbV6Q2jLLD1JBYixgGkskdfP3XFYgUixCdis4IgkY~piNQTzDYVezsHZgIWHu~HWp9qCZFA__\u0026Key-Pair-Id=DLVR"},"en-US":{"hardsub_locale":"en-US","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_,2232668_720_en-US.mp4,2232668_1080_en-US.mp4,2232668_480_en-US.mp4,2232668_360_en-US.mp4,.urlset/manifest.mpd?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiXywyMjMyNjY4XzcyMF9lbi1VUy5tcDQsMjIzMjY2OF8xMDgwX2VuLVVTLm1wNCwyMjMyNjY4XzQ4MF9lbi1VUy5tcDQsMjIzMjY2OF8zNjBfZW4tVVMubXA0LC51cmxzZXQvbWFuaWZlc3QubXBkIiwiQ29uZGl0aW9uIjp7IkRhdGVMZXNzVGhhbiI6eyJBV1M6RXBvY2hUaW1lIjoxNTM4OTg4NjUwfX19XX0_\u0026Signature=FhoYCjxXrnYbgRDSbVydK0r3rYjyCwHFG-jHDoJcbQhYiLaAgZS5h9Q59cv31y~tOsOJbjfIqFhNAKOQJ8mOiJl67kp~AxDCX6LamsI9IbEW6HDS3mzlZ~kOoLCKE7PaKCJIrAcfi9rID~hv48lf0eXA0-wUHwoiimOwuG12w3QpgH67oOfbDFSHU-ml2mGNwL7-QHwMLJ8IqaLRK6s8Jc3MLhSNJmXdoYkOM6CINcqiUB867GMPzYyN1EwBupAnr4QksR79jIXfpWjeZR7GLkihGaZw~ef3VSTd8Zr5vYsCEHLkgo7fqnmbgjn~hwsYRXxpNNTMjrtLSCPO8NI4nw__\u0026Key-Pair-Id=DLVR"}},"adaptive_hls":{"":{"hardsub_locale":"","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_,2232668_720.mp4,2232668_1080.mp4,2232668_480.mp4,2232668_360.mp4,.urlset/master.m3u8?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiXywyMjMyNjY4XzcyMC5tcDQsMjIzMjY2OF8xMDgwLm1wNCwyMjMyNjY4XzQ4MC5tcDQsMjIzMjY2OF8zNjAubXA0LC51cmxzZXQvbWFzdGVyLm0zdTgiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE1Mzg5ODg2NTB9fX1dfQ__\u0026Signature=DRc-r9ggXddNwHasA3dC8dmbuZC3hOLT4oy3VySqZClCOjbttkT7R5oB6irVMTY5yNh3k8Eaz-4hIhOUIQOCTvZQ0U-bD7mJVPN7cayvyALUDPAU1O5MNzA4IEHCRPh4K39KPvkP7Sz7ND-d0AKC6jpcqDSJgQI0Oz8d~nsr44lzleFhLEJFSF2jt4yXYrngrkqkP5I8c3jNYBBcWMewjZ26ue~UzC6F4shJuMg8QJFwOewq8jpDN7tM6ad8s~CTvZIiAEL8h6O2eR8iANUsF4i-4k0FNmLbbpj0WKIY3G5Kv4luo5hHBZiihR06rQ60caCSQMSZ1fmN2twOeTllWg__\u0026Key-Pair-Id=DLVR"},"en-US":{"hardsub_locale":"en-US","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_,2232668_720_en-US.mp4,2232668_1080_en-US.mp4,2232668_480_en-US.mp4,2232668_360_en-US.mp4,.urlset/master.m3u8?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiXywyMjMyNjY4XzcyMF9lbi1VUy5tcDQsMjIzMjY2OF8xMDgwX2VuLVVTLm1wNCwyMjMyNjY4XzQ4MF9lbi1VUy5tcDQsMjIzMjY2OF8zNjBfZW4tVVMubXA0LC51cmxzZXQvbWFzdGVyLm0zdTgiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE1Mzg5ODg2NTB9fX1dfQ__\u0026Signature=srwC7XbGKhKtjSyfSeo~r5VZG1W7RceV4J3OW1MkZ0t16XAPiwhbrC4sbD6Zr8r2k69Ii8AW767z46tLHXio5a~ZabzOpDzrVxy6i2dAK8GZM9myqxnTZvS7hJV6we3Mmkl7AxawkVA2NVdkKSid88x81SoWjiJZ2tbCbVKRlhtjVX-kS2K-gPYKqUcLBST7ZWTcxDHlbyKsjWFJsdCoVDBY7KFPKC4geaslAEQQt4raXHKCyrfZ8fJ4fmKZ4hOaCSMQpDF7TiIF5AHCwbiSCtbbpyLJbU3nHhxZhyHIH96k2VjpwH4KWJ9cKJi9UERshAD-pRPS1Q7lD2mTG~TScA__\u0026Key-Pair-Id=DLVR"}},"download_hls":{"":{"hardsub_locale":"","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_,2232668_480.mp4,.urlset/master.m3u8?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiXywyMjMyNjY4XzQ4MC5tcDQsLnVybHNldC9tYXN0ZXIubTN1OCIsIkNvbmRpdGlvbiI6eyJEYXRlTGVzc1RoYW4iOnsiQVdTOkVwb2NoVGltZSI6MTUzODk4ODY1MH19fV19\u0026Signature=FoPuW9-LTD2l0WuhDeARWbyv1MB38mp8CWkjfPHpSk035GhBE2RKYKbOIXVOiLK4Bfr8~yuiY7XmeyHjClfwHa9ixUxppLyNvfEBpeFfXpoR8WCVOsWNk-EcB17d2Wls915mnRJGVkbdubEFqrliCVFzhPZKTlXHVlRYEY~bHhn5TV-frCGiNugrS~pTn6GSreIlxiyv5irGTx2gPF9b0~LFBA4wq7Oib7y8vS4nz1pt5vQmPheBTjIxb2lYcdICm2~2riK0ncqcJQcP1BFtMHu06dCTPyN9vHctvWT0ENs99Cw4u9XUq7bCug3PUNep9Xo29Cu54Q8D6avJ2MhlaQ__\u0026Key-Pair-Id=DLVR"}},"multitrack_adaptive_hls_v2":{"":{"hardsub_locale":"","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_,2232668_720.mp4,2232668_1080.mp4,2232668_480.mp4,2232668_360.mp4,timed_text_subtitle_en-US.ssa,.urlset/master.m3u8?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiXywyMjMyNjY4XzcyMC5tcDQsMjIzMjY2OF8xMDgwLm1wNCwyMjMyNjY4XzQ4MC5tcDQsMjIzMjY2OF8zNjAubXA0LHRpbWVkX3RleHRfc3VidGl0bGVfZW4tVVMuc3NhLC51cmxzZXQvbWFzdGVyLm0zdTgiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE1Mzg5ODg2NTB9fX1dfQ__\u0026Signature=nKFaMzY3qUuXdCUaYW7AG-PnLcNwKJ7yNS0o2m7sV-N0W0PoREfCHDB-VvC1UlVyp27mJmITw70aCw0cIidUDTivJav4r25peR-Xzm0wbFtPDZJI6FwfFfEAXW0TZ-8kWzxcnWOB-Rrv4LeyK75M5lNHhQs5271t-3siMAid2tQNim~xVJpLRwomeFgRzRjO9yJvSxlVnlrUM4aid6SmpWpvotiaO7wQmWI8OzcCInNp5BCqghZjXah9xOzyR3Rb0M~WfgXzpLIlfi7iTdk9X~1525NKB3917XMZXIrAG7QEa4WO0e2FFIY8gjVeRMgTVPxBOYGO7cGFc36ZTMSHwQ__\u0026Key-Pair-Id=DLVR"},"en-US":{"hardsub_locale":"en-US","url":"https://dl.v.vrv.co/evs/e33b9ef0967783dee64eefb783eaa560/assets/1d6b395a36afab5fbe6256953726b6fb_,2232668_720_en-US.mp4,2232668_1080_en-US.mp4,2232668_480_en-US.mp4,2232668_360_en-US.mp4,timed_text_subtitle_en-US.ssa,.urlset/master.m3u8?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cCo6Ly9kbC52LnZydi5jby9ldnMvZTMzYjllZjA5Njc3ODNkZWU2NGVlZmI3ODNlYWE1NjAvYXNzZXRzLzFkNmIzOTVhMzZhZmFiNWZiZTYyNTY5NTM3MjZiNmZiXywyMjMyNjY4XzcyMF9lbi1VUy5tcDQsMjIzMjY2OF8xMDgwX2VuLVVTLm1wNCwyMjMyNjY4XzQ4MF9lbi1VUy5tcDQsMjIzMjY2OF8zNjBfZW4tVVMubXA0LHRpbWVkX3RleHRfc3VidGl0bGVfZW4tVVMuc3NhLC51cmxzZXQvbWFzdGVyLm0zdTgiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE1Mzg5ODg2NTB9fX1dfQ__\u0026Signature=lQq7D59CVP85YMboJt2uGrRaFF1020mBttwE8S16R2NbUG8KEnqW4jbnpi~RNkEBs3txbVt2SNibzvaEyxriCaVLY8rsRmTv-ZCh9V7D9DuT1-f309MxNOyr6Ks2hgA4snTY7rWrEqYpEzwE2RGRY2TE-ATXzNDz5iaYy4-mAAJgjl6pI2jAFUv-Ku-SstZECkCrONU5TP8-ldkxyAUfzs2We2reHjxjaLbWbgV05WpFmTDlYWd-SgBE6nJB~C4mmJv4lcnJABBFvFoklciWvBoER62k10YMupkPaSEZQypA2rl~QwX9hvLkAM500IN8PolJcjPCcImlu8dFKxxisQ__\u0026Key-Pair-Id=DLVR"}},"urls":{"":{"hardsub_locale":"","url":""}}}}')
            #streams_json = self._call_api(streams_path, video_id, 'streams')
            #streams_json = self._call_cms(streams_path, video_id, 'streams')

        audio_locale = streams_json.get('audio_locale')
        formats = []
        for stream_type, streams in streams_json.get('streams', {}).items():
            if stream_type in ('adaptive_hls', 'adaptive_dash'):
                for stream in streams.values():
                    formats.extend(self._extract_vrv_formats(
                        stream.get('url'), video_id, stream_type.split('_')[1],
                        audio_locale, stream.get('hardsub_locale')))
        self._sort_formats(formats)

        subtitles = {}
        for subtitle in streams_json.get('subtitles', {}).values():
            subtitle_url = subtitle.get('url')
            if not subtitle_url:
                continue
            subtitles.setdefault(subtitle.get('locale', 'en-US'), []).append({
                'url': subtitle_url,
                'ext': subtitle.get('format', 'ass'),
            })

        thumbnails = []
        for thumbnail in video_data.get('images', {}).get('thumbnails', []):
            thumbnail_url = thumbnail.get('source')
            if not thumbnail_url:
                continue
            thumbnails.append({
                'url': thumbnail_url,
                'width': int_or_none(thumbnail.get('width')),
                'height': int_or_none(thumbnail.get('height')),
            })

        return {
            'id': video_id,
            'title': title,
            'formats': formats,
            'subtitles': subtitles,
            'thumbnails': thumbnails,
            'description': video_data.get('description'),
            'duration': float_or_none(video_data.get('duration_ms'), 1000),
            'uploader_id': video_data.get('channel_id'),
            'series': video_data.get('series_title'),
            'season': video_data.get('season_title'),
            'season_number': int_or_none(video_data.get('season_number')),
            'season_id': video_data.get('season_id'),
            'episode': title,
            'episode_number': int_or_none(video_data.get('episode_number')),
            'episode_id': video_data.get('production_episode_id'),
        }


class VRVSeriesIE(VRVBaseIE):
    IE_NAME = 'vrv:series'
    _VALID_URL = r'https?://(?:www\.)?vrv\.co/series/(?P<id>[A-Z0-9]+)'
    _TEST = {
        'url': 'https://vrv.co/series/G68VXG3G6/The-Perfect-Insider',
        'info_dict': {
            'id': 'G68VXG3G6',
        },
        'playlist_mincount': 11,
    }

    def _real_extract(self, url):
        series_id = self._match_id(url)
        webpage = self._download_webpage(
            url, series_id,
            headers=self.geo_verification_headers())

        self._set_api_params(webpage, series_id)
        seasons_path = self._get_cms_resource(
            'cms:/seasons?series_id=' + series_id, series_id)
        seasons_data = self._call_cms(seasons_path, series_id, 'seasons')

        entries = []
        for season in seasons_data.get('items', []):
            episodes_path = season['__links__']['season/episodes']['href']
            episodes = self._call_cms(episodes_path, series_id, 'episodes')
            for episode in episodes.get('items', []):
                episode_id = episode['id']
                entries.append(self.url_result(
                    'https://vrv.co/watch/' + episode_id,
                    'VRV', episode_id, episode.get('title')))

        return self.playlist_result(entries, series_id)
