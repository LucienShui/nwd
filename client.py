import json as json_lib
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from urllib.parse import urlparse, urlencode, ParseResult


class Response:
    def __init__(self, response: HTTPResponse):
        self.response = response
        self._text: str = ...

    def is_success(self):
        return 200 <= self.response.status < 300

    def json(self):
        return json_lib.loads(self.text)

    @property
    def text(self):
        if self._text is ...:
            self._text = self.response.read().decode()
        return self._text

    @property
    def status_code(self):
        return self.response.status


class Client:
    def __init__(self, base_url: str = "", headers: dict = None):
        self.base_url = base_url
        self.headers = headers or {}
        self.cookies = {}

    @classmethod
    def _get_connection(cls, url) -> tuple[HTTPConnection | HTTPSConnection, ParseResult]:
        parsed_url = urlparse(url)
        connection = (HTTPConnection if parsed_url.scheme == "http" else HTTPSConnection)(parsed_url.netloc)
        return connection, parsed_url

    def _update_cookies(self, response):
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.get_all('Set-Cookie')
            for cookie in cookies:
                key, value = cookie.split(';', 1)[0].split('=', 1)
                self.cookies[key] = value

    def _get_cookie_header(self):
        return '; '.join([f"{key}={value}" for key, value in self.cookies.items()])

    def _request(self, method: str, url: str, *,
                 body: str | None = None,
                 params: dict | None = None,
                 headers: dict | None = None) -> Response:
        full_url = f"{self.base_url}{url}"
        if params:
            query_string = urlencode(params)
            full_url = f"{full_url}?{query_string}"
        connection, parsed_url = self._get_connection(full_url)
        headers = self.headers | (headers or {})
        if self.cookies:
            headers = headers | {"Cookie": self._get_cookie_header()}
        connection.request(method, parsed_url.path, body, headers=headers)
        response = connection.getresponse()
        self._update_cookies(response)
        return Response(response)

    def post(self, url: str, json: dict | None = None, headers: dict | None = None) -> Response:
        body = json_lib.dumps(json, ensure_ascii=False, separators=(',', ':')) if json else None
        headers = ({"Content-Type": "application/json"} if json else None) | (headers or {})
        return self._request("POST", url, body=body, headers=headers)

    def get(self, url: str, params: dict | None = None, headers: dict | None = None) -> Response:
        return self._request("GET", url, params=params, headers=headers)

    def head(self, url: str, headers: dict | None = None) -> Response:
        return self._request("HEAD", url, headers=headers)
