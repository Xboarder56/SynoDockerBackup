import requests
import socket
import json
import urllib3
import logging
import os
from urllib.parse import urlencode, quote_plus

dsm_host = ""
dsm_port = "5001"
user_name = ""
password = ""
output_path = "/volume1/Backup/Docker"
https = True


def main(dsm_host, dsm_port, user_name, password, output_path, https=None):
    params = {
        "account": user_name,
        "passwd": password,
        "enable_syno_token": "yes",
        "enable_device_token": "no",
        "device_name": socket.gethostname(),
        "format": "sid",
        "api": "SYNO.API.Auth",
        "version": "6",
        "method": "login"
    }


    if https:
        urllib3.disable_warnings()
        syno_server_url = f"https://{dsm_host}:{dsm_port}"
    else:
        syno_server_url = f"http://{dsm_host}:{dsm_port}"

    with requests.Session() as s:
        auth_url = f"{syno_server_url}/webapi/auth.cgi?{urlencode(params, quote_via=quote_plus)}"
        response = s.get(auth_url, verify=False)
        if response.json().get("success", False):
            logging.info("Logged into DSM Successfully")
            sid = response.json()["data"]["sid"]
            SynoToken = response.json()["data"]["synotoken"]

            def docker_images(sid, SynoToken):
                """Pull Docker Image Names"""
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-SYNO-TOKEN": SynoToken,
                }

                cookies = {
                    "id": sid,
                }

                payload = {
                    "api": "SYNO.Docker.Container",
                    "method": "list",
                    "version": "1",
                    "limit": "-1",
                    "offset": "0",
                    "type": "all"
                }
                result = s.post(f"{syno_server_url}/webapi/entry.cgi", cookies=cookies, data=payload,
                                headers=headers)
                containers = []
                for container in result.json()["data"].get("containers", []):
                    containers.append(container.get("name"))
                return containers

            containers = docker_images(sid, SynoToken)

            for container_name in containers:
                logging.debug("Found Container: %s", container_name)

                def docker_pull(image, sid, SynoToken, output_path):
                    """Pull Docker Config and Write to file"""
                    cookies = {
                        "id": sid,
                    }

                    docker_url = f'{syno_server_url}/webapi/entry.cgi?api=SYNO.Docker.Container.Profile&method=export&version=1&name=%22{image}%22&SynoToken={SynoToken}'
                    response = s.get(docker_url, cookies=cookies)

                    if 200 <= response.status_code < 203:
                        logging.info(f"Successfully pulled {image} config.")
                        file_path = os.path.join(output_path, f"{image}.json")

                        # Write Config File
                        syno_docker_config_file = open(file_path, 'w')
                        syno_docker_config_file.write(json.dumps(response.json(), indent=4))
                        syno_docker_config_file.close()
                    else:
                        logging.error(f"Unable to pull image {image}: %s", response.content)

                docker_pull(container_name, sid, SynoToken, output_path)
            logging.info("Successfully Backed up container configs to: %s", output_path)
            exit(0) # Exit
        else:
            logging.error("Failed to log into DSM: %s", response.content)
            exit(1)  # Exit with Error


if __name__ == '__main__':
    main(dsm_host, dsm_port, user_name, password, output_path, https)
