import json
import requests
from pymisp import MISPEvent, MISPObject, MISPAttribute

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-dst", "ip-src", "vulnerability"], "output": ["text"]}
moduleinfo = {
    "version": "1.1",
    "author": "Brad Chiappetta <brad@greynoise.io>",
    "description": "Module to access GreyNoise.io API.",
    "module-type": ["hover"],
}
moduleconfig = ["api_key", "api_type"]
codes_mapping = {
    "0x00": "The IP has never been observed scanning the Internet",
    "0x01": "The IP has been observed by the GreyNoise sensor network",
    "0x02": "The IP has been observed scanning the GreyNoise sensor network, "
    "but has not completed a full connection, meaning this can be spoofed",
    "0x03": "The IP is adjacent to another host that has been directly observed by the GreyNoise sensor network",
    "0x04": "Reserved",
    "0x05": "This IP is commonly spoofed in Internet-scan activity",
    "0x06": "This IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled frequently",
    "0x07": "This IP is invalid",
    "0x08": "This IP was classified as noise, but has not been observed engaging in Internet-wide scans or attacks in over 90 days",
    "0x09": "IP was found in RIOT",
    "0x10": "IP has been observed by the GreyNoise sensor network and is in RIOT",
}
vulnerability_mapping = {
    'id': ('vulnerability', 'CVE #'),
    'details': ('text', 'Details'),
    'count': ('text', 'Total Scanner Count')}
misp_event = MISPEvent()


def handler(q=False):  # noqa: C901
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config") or not request["config"].get("api_key"):
        return {"error": "Missing Greynoise API key."}

    headers = {
        "Accept": "application/json",
        "key": request["config"]["api_key"],
        "User-Agent": "greynoise-misp-module-{}".format(moduleinfo["version"]),
    }

    if not (request.get("vulnerability") or request.get("ip-dst") or request.get("ip-src")):
        misperrors["error"] = "Vulnerability id missing"
        return misperrors

    ip = ""
    vulnerability = ""

    if request.get("ip-dst"):
        ip = request.get("ip-dst")
    elif request.get("ip-src"):
        ip = request.get("ip-src")
    else:
        vulnerability = request.get('vulnerability')

    if ip:
        if request["config"]["api_type"] and request["config"]["api_type"] == "enterprise":
            greynoise_api_url = "https://api.greynoise.io/v2/noise/quick/"
        else:
            greynoise_api_url = "https://api.greynoise.io/v3/community/"

        response = requests.get(f"{greynoise_api_url}{ip}", headers=headers)  # Real request for IP Query
        if response.status_code == 200:
            if request["config"]["api_type"] == "enterprise":
                return {
                    "results": [
                        {
                            "types": ["text"],
                            "values": codes_mapping[response.json()["code"]],
                        }
                    ]
                }
            elif response.json()["noise"]:
                return {
                    "results": [
                        {
                            "types": ["text"],
                            "values": "IP Address ({}) has been observed by GreyNoise "
                            "scanning the internet in the last 90 days. GreyNoise has "
                            "classified it as {} and it was last seen on {}. For more "
                            "information visit {}".format(
                                response.json()["ip"],
                                response.json()["classification"],
                                response.json()["last_seen"],
                                response.json()["link"],
                            ),
                        }
                    ]
                }
            elif response.json()["riot"]:
                return {
                    "results": [
                        {
                            "types": ["text"],
                            "values": "IP Address ({}) is part of GreyNoise Project RIOT "
                            "and likely belongs to a benign service from {}.  For more "
                            "information visit {}".format(
                                response.json()["ip"],
                                response.json()["name"],
                                response.json()["link"],
                            ),
                        }
                    ]
                }

    if vulnerability:
        if request["config"]["api_type"] and request["config"]["api_type"] == "enterprise":
            greynoise_api_url = "https://api.greynoise.io/v2/experimental/gnql/stats"
            querystring = {f"query": f"last_seen:1w cve:{vulnerability}"}
        else:
            misperrors["error"] = "Vulnerability Not Supported with Community API Key"
            return misperrors

        response = requests.get(f"{greynoise_api_url}", headers=headers, params=querystring)  # Real request

        if response.status_code == 200:
            response = response.json()
            vulnerability_object = MISPObject('vulnerability')
            response["details"] = "The Count below reflects the Number of IPs seen by " \
                                  "GreyNoise in the last 7 days scanning for this CVE."
            response["id"] = vulnerability
            for feature in ('id', 'details', 'count'):
                value = response.get(feature)
                if value:
                    attribute_type, relation = vulnerability_mapping[feature]
                    vulnerability_object.add_attribute(relation,
                                                       **{'type': attribute_type,
                                                          'value': value})
            classifications = response.get(response["stats"]["classifications"])
            for item in classifications:
                if item["classification"] == "benign":
                    value = item["count"]
                    attribute_type, relation = ('text', 'Benign Scanner Count')
                    vulnerability_object.add_attribute(relation,
                                                       **{'type': attribute_type,
                                                          'value': value})
                if item["classification"] == "unknown":
                    value = item["count"]
                    attribute_type, relation = ('text', 'Unknown Scanner Count')
                    vulnerability_object.add_attribute(relation,
                                                       **{'type': attribute_type,
                                                          'value': value})
                if item["classification"] == "malicious":
                    value = item["count"]
                    attribute_type, relation = ('text', 'Malicious Scanner Count')
                    vulnerability_object.add_attribute(relation,
                                                       **{'type': attribute_type,
                                                          'value': value})
            misp_event.add_object(vulnerability_object)
            event = json.loads(misp_event.to_json())
            results = {key: event[key] for key in ('Attribute', 'Object') if
                       (key in event and event[key])}
            return {'results': results}

    # There is an error
    errors = {
        400: "Bad request.",
        404: "IP not observed scanning the internet or contained in RIOT data set.",
        401: "Unauthorized. Please check your API key.",
        429: "Too many requests. You've hit the rate-limit.",
    }
    try:
        misperrors["error"] = errors[response.status_code]
    except KeyError:
        misperrors["error"] = f"GreyNoise API not accessible (HTTP {response.status_code})"
    return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
