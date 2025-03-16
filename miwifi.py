# 小米路由器远程管理 API

import hashlib
import math
import random
import time

from client import Client, Response


class MiWiFi:
    """
    docstring for MiWiFi
    """

    def __init__(self, base_url: str):
        super(MiWiFi, self).__init__()

        self.type = '0'
        self.nonce = None
        self.password = None
        self.stok = None

        self.client = Client(base_url=base_url)

        # 小米路由器登录页面
        self.login_url = "/cgi-bin/luci/api/xqsystem/login"

    def nonce_create(self, miwifi_device_id):
        """
        模仿小米路由器的登录页面，计算 hash 所需的 nonce 值
        """
        miwifi_time = str(int(math.floor(time.time())))
        miwifi_random = str(int(math.floor(random.random() * 10000)))
        self.nonce = '_'.join([self.type, miwifi_device_id, miwifi_time, miwifi_random])

        return self.nonce

    def old_passwd(self, password, key):
        """
        模仿小米路由器的登录页面，计算密码的 hash
        """
        self.password = hashlib.sha1(self.nonce + hashlib.sha1(password + key).hexdigest()).hexdigest()

        return self.password

    def login(self, device_id, password, key) -> None:
        """
        登录小米路由器，并取得对应的 cookie 和用于拼接 URL 所需的 stok
        """
        nonce = self.nonce_create(device_id)
        password = self.old_passwd(password, key)
        payload = {'username': 'admin', 'logtype': '2', 'password': password, 'nonce': nonce}

        try:
            r: Response = self.client.post(self.login_url, params=payload)
            stok = r.json().get('url').split('=')[1].split('/')[0]
        except Exception as e:
            raise e

        self.stok = stok

    @property
    def url_action(self) -> str:
        return "/cgi-bin/luci/;stok=%s/api" % self.stok

    @property
    def url_device_list_daemon(self) -> str:
        return "%s/xqsystem/device_list" % self.url_action

    def list_device(self):
        """
        列出小米路由器上当前的设备清单
        """
        r = self.client.get(self.url_device_list_daemon)
        return r.json().get('list')

    def run_action(self, action):
        """
        run a custom action like "pppoe_status", "pppoe_stop", "pppoe_start" ...
        """
        r = self.client.get('%s/xqnetwork/%s' % (self.url_action, action))
        return r.json()
