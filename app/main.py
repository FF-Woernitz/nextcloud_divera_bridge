from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse

import requests
import logging
# 5649 = FFW
# 9685 = FFW Test
CLUSTERS = [5649]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

app = FastAPI()
security = HTTPBasic()


def return_error(msg="Unknown error during login"):
    logger.warning(msg)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=msg,
        headers={"WWW-Authenticate": "Basic"},
    )


def login_divera(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    logger.info(f"Start login for {credentials.username}")
    if credentials.username == "" or credentials.password == "":
        return_error("Emtpy username or password")

    r = requests.post('https://www.divera247.com/api/v2/auth/login', json={
        "Login": {
            "username": credentials.username,
            "password": credentials.password,
            "jwt": False
        }
    })
    resp_login = r.json()
    if not resp_login["success"]:
        return_error("Divera Login failed #1")

    try:
        if resp_login["data"]["user"]["access_token"] == "":
            return_error("Divera Login failed #2")
    except KeyError:
        return_error("Divera Login failed #3")

    accesskey = resp_login["data"]["user"]["access_token"]

    resp_cluster = requests.get('https://www.divera247.com/api/v2/pull/all', params={"accesskey": accesskey})
    resp_cluster = resp_cluster.json()
    if not resp_cluster["success"]:
        return_error("Divera UCR failed #1")
    clusters = {}
    for k, v in resp_cluster["data"]["ucr"].items():
        clusters[v["cluster_id"]] = k

    for cluster, ucr in clusters.items():
        if cluster in CLUSTERS:
            return {"username": credentials.username, "cluster": cluster, "ucr": ucr}

    return_error("Divera cluster failed")


@app.get("/login")
def divera_login(data: Annotated[dict, Depends(login_divera)]):
    logger.info(f"Successfully logged in: {data['username']}")
    return {"success": True, "data": data}


@app.get("/")
def read_root():
    return RedirectResponse("https://ffw-it.de")
