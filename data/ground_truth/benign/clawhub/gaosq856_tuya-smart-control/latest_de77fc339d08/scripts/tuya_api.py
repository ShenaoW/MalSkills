#!/usr/bin/env python3
"""Tuya Smart Home API SDK

Provides the TuyaAPI class, encapsulating all Tuya Open Platform 2C end-user
API call logic. Supports both Python code invocation and command-line mode.

Credentials are read from environment variables. TUYA_API_KEY is required;
TUYA_BASE_URL is optional — the base URL is auto-detected from the API key
prefix (e.g. sk-AY... → China, sk-AZ... → US, sk-EU... → Europe).
"""

import json
import os
import sys
import requests

# API key prefix → data center base URL mapping
_PREFIX_TO_BASE_URL = {
    "AY": "https://openapi.tuyacn.com",   # China Data Center
    "AZ": "https://openapi.tuyaus.com",   # US West Data Center
    "EU": "https://openapi.tuyaeu.com",   # Central Europe Data Center
    "IN": "https://openapi.tuyain.com",   # India Data Center
    "UE": "https://openapi-ueaz.tuyaus.com",  # US East Data Center
    "WE": "https://openapi-weaz.tuyaeu.com",  # Western Europe Data Center
    "SG": "https://openapi-sg.iotbing.com",   # Singapore Data Center
}


def _resolve_base_url(api_key: str) -> str:
    """Resolve base URL from the API key prefix.

    API key format: sk-<PREFIX><rest>
    Example: sk-AY12c7ee31ae19*********57d → prefix AY → China
    """
    key = api_key
    if key.startswith("sk-"):
        key = key[3:]
    prefix = key[:2].upper()
    if prefix in _PREFIX_TO_BASE_URL:
        return _PREFIX_TO_BASE_URL[prefix]
    raise ValueError(
        f"Cannot determine data center from API key prefix '{prefix}'. "
        f"Supported prefixes: {', '.join(sorted(_PREFIX_TO_BASE_URL.keys()))}. "
        f"Please set TUYA_BASE_URL explicitly."
    )


class TuyaAPI:
    """Tuya Open Platform 2C end-user API client"""

    def __init__(self, api_key: str = None, base_url: str = None):
        if api_key is None:
            api_key = os.environ.get("TUYA_API_KEY")
        if base_url is None:
            base_url = os.environ.get("TUYA_BASE_URL")
        if not api_key:
            raise ValueError(
                "Missing API key. Set environment variable TUYA_API_KEY, "
                "or pass api_key argument."
            )
        if not base_url:
            base_url = _resolve_base_url(api_key)
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
        })

    # ─── Common Requests ───

    def _get(self, path: str, params: dict = None):
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, params=params)
        return resp.json()

    def _post(self, path: str, data: dict = None):
        url = f"{self.base_url}{path}"
        resp = self.session.post(url, json=data)
        return resp.json()

    # ─── Home Management ───

    def get_homes(self):
        """Query all homes for the user"""
        return self._get("/v1.0/end-user/homes/all")

    def get_rooms(self, home_id: str):
        """Query all rooms in a home"""
        return self._get(f"/v1.0/end-user/homes/{home_id}/rooms")

    # ─── Device Query ───

    def get_all_devices(self):
        """Query all devices for the user"""
        return self._get("/v1.0/end-user/devices/all")

    def get_home_devices(self, home_id: str):
        """Query all devices in a home"""
        return self._get(f"/v1.0/end-user/homes/{home_id}/devices")

    def get_room_devices(self, room_id: str):
        """Query all devices in a room"""
        return self._get(f"/v1.0/end-user/homes/room/{room_id}/devices")

    def get_device_detail(self, device_id: str):
        """Query single device detail (including current property states)"""
        return self._get(f"/v1.0/end-user/devices/{device_id}/detail")

    # ─── Device Control ───

    def get_device_model(self, device_id: str):
        """Query device Thing Model"""
        return self._get(f"/v1.0/end-user/devices/{device_id}/model")

    def issue_properties(self, device_id: str, properties: dict):
        """Issue property commands to a device

        Args:
            device_id: Device ID
            properties: Property key-value pairs, e.g. {"switch_led": True, "bright_value": 500}
                       Automatically serialized to a JSON string
        """
        return self._post(
            f"/v1.0/end-user/devices/{device_id}/shadow/properties/issue",
            data={"properties": json.dumps(properties)},
        )

    # ─── Device Management ───

    def rename_device(self, device_id: str, name: str):
        """Rename a device"""
        return self._post(
            f"/v1.0/end-user/devices/{device_id}/attribute",
            data={"name": name},
        )

    # ─── Weather Service ───

    def get_weather(self, lat: str, lon: str, codes: list = None):
        """Query weather information

        Args:
            lat: Latitude
            lon: Longitude
            codes: Weather attribute list, defaults to temperature, humidity,
                   and condition for the next 7 hours
        """
        if codes is None:
            codes = ["w.temp", "w.humidity", "w.condition", "w.hour.7"]
        return self._get(
            "/v1.0/end-user/services/weather/recent",
            params={"lat": lat, "lon": lon, "codes": json.dumps(codes)},
        )

    # ─── Notifications ───

    def send_sms(self, message: str):
        """Send an SMS to the current user"""
        return self._post(
            "/v1.0/end-user/services/sms/self-send",
            data={"message": message},
        )

    def send_voice(self, message: str):
        """Send a voice notification to the current user"""
        return self._post(
            "/v1.0/end-user/services/voice/self-send",
            data={"message": message},
        )

    def send_mail(self, subject: str, content: str):
        """Send an email to the current user"""
        return self._post(
            "/v1.0/end-user/services/mail/self-send",
            data={"subject": subject, "content": content},
        )

    def send_push(self, subject: str, content: str):
        """Send an App push notification to the current user"""
        return self._post(
            "/v1.0/end-user/services/push/self-send",
            data={"subject": subject, "content": content},
        )

    # ─── Data Statistics ───

    def get_statistics_config(self):
        """Query hourly statistics configuration for all user devices"""
        return self._get("/v1.0/end-user/statistics/hour/config")

    def get_statistics_data(self, dev_id: str, dp_code: str,
                           statistic_type: str, start_time: str,
                           end_time: str):
        """Query hourly statistics values for a device

        Args:
            dev_id: Device ID
            dp_code: Data point code (e.g. ele_usage)
            statistic_type: Statistic type (SUM, COUNT, MAX, MIN, MINUX)
            start_time: Start time, format yyyyMMddHH
            end_time: End time, format yyyyMMddHH (max 24-hour span from start)
        """
        return self._get(
            "/v1.0/end-user/statistics/hour/data",
            params={
                "dev_id": dev_id,
                "dp_code": dp_code,
                "statistic_type": statistic_type,
                "start_time": start_time,
                "end_time": end_time,
            },
        )


# ─── Command-Line Mode ───

def _print_json(data):
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main():
    if len(sys.argv) < 2:
        print("Usage: python tuya_api.py <command> [params...]")
        print()
        print("TUYA_API_KEY is required. TUYA_BASE_URL is optional (auto-detected from key prefix).")
        print()
        print("Commands:")
        print("  homes                                  List all homes")
        print("  rooms <home_id>                        List rooms in a home")
        print("  devices                                List all devices")
        print("  home_devices <home_id>                 List devices in a home")
        print("  room_devices <room_id>                 List devices in a room")
        print("  device_detail <device_id>              Get device detail")
        print("  model <device_id>                      Get device Thing Model")
        print("  control <device_id> <properties_json>  Control a device")
        print("  rename <device_id> <new_name>          Rename a device")
        print("  weather <lat> <lon> [codes_json]       Query weather")
        print("  sms <message>                          Send SMS")
        print("  voice <message>                        Send voice call")
        print("  mail <subject> <content>               Send email")
        print("  push <subject> <content>               Send push notification")
        print("  stats_config                           Query statistics config")
        print("  stats_data <dev_id> <dp_code> <type> <start> <end>  Query statistics")
        sys.exit(1)

    api = TuyaAPI()
    command = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        "homes": lambda: api.get_homes(),
        "rooms": lambda: api.get_rooms(args[0]),
        "devices": lambda: api.get_all_devices(),
        "home_devices": lambda: api.get_home_devices(args[0]),
        "room_devices": lambda: api.get_room_devices(args[0]),
        "device_detail": lambda: api.get_device_detail(args[0]),
        "model": lambda: api.get_device_model(args[0]),
        "control": lambda: api.issue_properties(args[0], json.loads(args[1])),
        "rename": lambda: api.rename_device(args[0], args[1]),
        "weather": lambda: api.get_weather(
            args[0], args[1],
            json.loads(args[2]) if len(args) > 2 else None
        ),
        "sms": lambda: api.send_sms(args[0]),
        "voice": lambda: api.send_voice(args[0]),
        "mail": lambda: api.send_mail(args[0], args[1]),
        "push": lambda: api.send_push(args[0], args[1]),
        "stats_config": lambda: api.get_statistics_config(),
        "stats_data": lambda: api.get_statistics_data(
            args[0], args[1], args[2], args[3], args[4]
        ),
    }

    if command not in commands:
        print(f"Unknown command: {command}")
        sys.exit(1)

    _print_json(commands[command]())


if __name__ == "__main__":
    main()
