import os
import re
import socket
from datetime import datetime

import httpx

from logger import get_logger

IP_PATTERN = re.compile(r'\d+\.\d+\.\d+\.\d+')
logger = get_logger(str(int(datetime.now().timestamp())))


def assert_response(response: httpx.Response) -> httpx.Response:
    assert response.is_success, response.text
    return response


class IKuai:
    def __init__(self, username: str, md5_password: str, url: str):
        self.client = httpx.Client(base_url=url)

        json_response = assert_response(
            self.client.post('/Action/login', json={'username': username, 'passwd': md5_password})
        ).json()
        assert json_response['Result'] == 10000 and json_response['ErrMsg'] == 'Success', json_response['ErrMsg']

    def post(self, json: dict) -> dict:
        return assert_response(self.client.post('/Action/call', json=json)).json()


class Cloudflare:
    def __init__(self, email: str, global_api_key: str):
        self.client = httpx.Client(
            base_url="https://api.cloudflare.com/client/v4",
            headers={
                "X-Auth-Email": email,
                "X-Auth-Key": global_api_key,
                # "Authorization": f"Bearer {self.token}"
            }
        )

    def get_zone_id(self, domain: str) -> str:
        # https://developers.cloudflare.com/api/resources/zones/methods/get/
        response = assert_response(self.client.get("/zones")).json()
        for zone in response["result"]:
            name: str = zone["name"]
            if name == domain or domain.endswith(f".{name}"):
                return zone["id"]
        raise RuntimeError("Zone not found")

    def get_dns_record_detail(self, domain: str, zone_id: str) -> (str, str):
        # https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/
        response = assert_response(self.client.get(f"/zones/{zone_id}/dns_records", params={"name": domain})).json()
        for record in response["result"]:
            if record["name"] == domain:
                return record["id"], record["content"]
        raise RuntimeError("DNS record not found")

    def patch_dns_record(
            self,
            domain: str,
            ip: str,
            comment: str | None = None,
    ):
        # https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/
        zone_id: str = self.get_zone_id(domain)
        dns_record_id, record_ip = self.get_dns_record_detail(domain, zone_id)
        if ip != record_ip:
            response = assert_response(self.client.patch(f"/zones/{zone_id}/dns_records/{dns_record_id}", json={
                "content": ip,
                "comment": comment or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })).json()
            logger.info({
                "message": "patch_dns_record",
                "record_ip": record_ip,
                "domain": domain,
                "ip": ip,
                "response": response
            })
        else:
            logger.info({"message": "skip_patch_dns_record", "domain": domain, "ip": ip})


def get_wan_ip(ikuai: IKuai, wan_id: int) -> str:
    response = ikuai.post({"func_name": "wan", "action": "show", "param": {"id": str(wan_id), "TYPE": "data"}})
    data = response["Data"]["data"][0]
    return data["pppoe_ip_addr"]


def wan_reconnect(ikuai: IKuai, wan_id: int) -> dict:
    return ikuai.post({"func_name": "wan", "action": "link_pppoe_reconnect", "param": {"id": wan_id}})


def get_ip_from_api() -> str:
    response = httpx.get("http://myip.ipip.net").raise_for_status().text
    ip = IP_PATTERN.findall(response)[0]
    return ip


def resolve(domain: str) -> str:
    try:
        ip_addresses = []
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            if ip not in ip_addresses:
                ip_addresses.append(ip)
        return ip_addresses[0]
    except Exception as e:
        logger.exception({"message": "resolve", "domain": domain, "error": f"{e.__class__.__name__}: {str(e)}"})
        return ""


def check_connectivity(ip: str) -> bool:
    try:
        with httpx.Client() as client:
            response = client.head(f"http://{ip}:2016")
            return response.status_code == 302
    except Exception as e:
        logger.exception({"message": "check_connectivity", "ip": ip, "error": f"{e.__class__.__name__}: {str(e)}"})
        return False

def check_connectivity_with_retry(ip: str, retry_times: int = 3) -> bool:
    for i in range(retry_times):
        if check_connectivity(ip):
            return True
        logger.info({"message": "check_connectivity_with_retry", "ip": ip, "retry_times": i + 1})
    return False


def task():
    username: str = os.environ['IKUAI_USERNAME']
    md5_password: str = os.environ['IKUAI_MD5PASSWORD']
    ikuai_api = os.environ['IKUAI_API']
    wan_id = int(os.getenv("IKUAI_WAN_ID", "1"))

    email: str = os.environ['CF_EMAIL']
    global_api_key: str = os.environ['CF_GLOBAL_API_KEY']
    domain: str = os.environ['CF_DOMAIN']

    ikuai = IKuai(username, md5_password, ikuai_api)

    wan_ip = get_wan_ip(ikuai, wan_id)
    wan_ip_connectivity = check_connectivity_with_retry(wan_ip, 3)
    api_ip = get_ip_from_api()
    dns_record_ip = resolve(domain)

    logger.info({
        "wan_ip": wan_ip,
        "api_ip": api_ip,
        "dns_record_ip": dns_record_ip,
        "wan_ip_connectivity": wan_ip_connectivity
    })

    if wan_ip != api_ip or (not wan_ip_connectivity):
        logger.info({"message": "before_reconnect"})
        response = wan_reconnect(ikuai, wan_id)
        logger.info({"message": "reconnect", "response": response})
    elif wan_ip != dns_record_ip:
        c = Cloudflare(email, global_api_key)
        c.patch_dns_record(domain, wan_ip)
    else:
        logger.info({"message": "skip"})


def main():
    try:
        task()
    except Exception as e:
        logger.exception({"message": "main", "error": f"{e.__class__.__name__}: {str(e)}"})


if __name__ == '__main__':
    main()