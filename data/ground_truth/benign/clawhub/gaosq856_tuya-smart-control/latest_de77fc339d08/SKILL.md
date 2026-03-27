---
name: tuya-smart-control
description: >
  tuya-smart-control is an official AI Agent skill for the OpenClaw platform, built on Tuya's 2C end-user APIs. It brings developers the industry's broadest AI + device interaction capabilities — 3,000+ smart hardware categories, covering 200+ countries and regions, enabling AI Agents to control everything out of the box. Get started with one click at tuya.ai — no complex authentication required. Once installed, use natural language to query devices, control smart hardware, send notifications, check weather, view data statistics, and more.
metadata:
  {
    "openclaw":
      {
        "emoji": "🏠",
        "name": "tuya-smart-control",
        "description": "tuya-smart-control is an official AI Agent skill for the OpenClaw platform, built on Tuya's 2C end-user APIs. It brings developers the industry's broadest AI + device interaction capabilities — 3,000+ smart hardware categories, covering 200+ countries and regions, enabling AI Agents to control everything out of the box. Get started with one click at tuya.ai — no complex authentication required. Once installed, use natural language to query devices, control smart hardware, send notifications, check weather, view data statistics, and more.",
        "requires": { "env": ["TUYA_API_KEY"], "pip": ["requests"] },
        "primaryEnv": "TUYA_API_KEY",
        "env": {
          "TUYA_API_KEY": { "label": "Tuya API Key", "description": "Your Tuya Open Platform API Key (base URL is auto-detected from key prefix, e.g. sk-AY... → China, sk-AZ... → US, sk-EU... → Europe)", "placeholder": "e.g. sk-AY12c7ee...", "required": true }
        }
      }
  }
---

# Tuya Smart Home Device Control Skill

## Basic Information

- **Official Website**: https://www.tuya.com/
- **Source Code**: https://github.com/tuya/tuya-openclaw-skills
- **Authentication**: Via Header `Authorization: Bearer {Api-key}`
- **Credentials**: Read from environment variable `TUYA_API_KEY`. The base URL is auto-detected from the API key prefix (e.g. `sk-AY...` → China, `sk-EU...` → Europe). You can override by setting `TUYA_BASE_URL`.
- **API Reference**: See individual files under `references/`
- **Python SDK**: See `scripts/tuya_api.py`, which provides a `TuyaAPI` class for calling all APIs directly

## Environment Variable Configuration

Set the following environment variable before use:

```bash
export TUYA_API_KEY="your-tuya-api-key"
# TUYA_BASE_URL is optional — auto-detected from API key prefix
# Override only if needed: export TUYA_BASE_URL="https://openapi.tuyaus.com"
```

### API Key Prefix → Data Center Mapping

The base URL is automatically resolved from the first two characters after `sk-` in the API key:

| Prefix | Region | Base URL |
|--------|--------|----------|
| AY | China Data Center | https://openapi.tuyacn.com |
| AZ | US West Data Center | https://openapi.tuyaus.com |
| EU | Central Europe Data Center | https://openapi.tuyaeu.com |
| IN | India Data Center | https://openapi.tuyain.com |
| UE | US East Data Center | https://openapi-ueaz.tuyaus.com |
| WE | Western Europe Data Center | https://openapi-weaz.tuyaeu.com |
| SG | Singapore Data Center | https://openapi-sg.iotbing.com |

How to obtain an API key:
- China Mainland users: Get from https://tuyasmart.com/
- International users: Get from https://tuya.ai/
- Different regions use different API service domains, which must match your account registration region

The skill will not load if the `TUYA_API_KEY` environment variable is missing.

## Usage

### Method 1: Via Python SDK (Recommended)

The skill provides `scripts/tuya_api.py`, containing a `TuyaAPI` class that encapsulates all API call logic. Usage:

```python
import sys
sys.path.insert(0, "{baseDir}/scripts")
from tuya_api import TuyaAPI

# Initialize from environment variables (recommended)
api = TuyaAPI()

# Query all homes
homes = api.get_homes()

# Query all devices
devices = api.get_all_devices()

# Query device detail
detail = api.get_device_detail("0620068884f3eb414579")

# Control device
result = api.issue_properties("0620068884f3eb414579", {"switch_led": True, "bright_value": 500})

# Query weather
weather = api.get_weather(lat="39.9042", lon="116.4074")
```

### Method 2: Via Command Line

With the environment variable set, simply pass the command:

```bash
python3 {baseDir}/scripts/tuya_api.py <command> [params...]

# Examples
python3 {baseDir}/scripts/tuya_api.py homes
python3 {baseDir}/scripts/tuya_api.py devices
python3 {baseDir}/scripts/tuya_api.py device_detail 0620068884f3eb414579
python3 {baseDir}/scripts/tuya_api.py control 0620068884f3eb414579 '{"switch_led":true}'
```

### Method 3: Via curl

```bash
curl -s -H "Authorization: Bearer $TUYA_API_KEY" "$TUYA_BASE_URL/v1.0/end-user/homes/all"
```

## Feature Overview

| Module | Capabilities | Reference |
|--------|-------------|-----------|
| Home Management | List all homes, list rooms in a home | `references/home-and-space.md` |
| Device Query | All devices, devices by home, devices by room, single device detail (including current property states) | `references/device-query.md` |
| Device Control | Query device Thing Model, issue property commands | `references/device-control.md` |
| Device Management | Rename device | `references/device-management.md` |
| Weather Service | Current and forecast weather | `references/weather.md` |
| Notifications | SMS, voice call, email, App push | `references/notifications.md` |
| Data Statistics | Hourly statistics config query, statistics value query | `references/statistics.md` |

## Core Workflows

### Workflow 1: Device Control

When the user says things like "turn on the living room light" or "set the AC temperature to 26 degrees":

1. **Locate the device** — Find the target device based on the device name or location mentioned by the user
   - User only mentions device name (e.g. "AC") -> Call the "List All Devices" API, fuzzy-match by device name
   - User mentions location + device name (e.g. "living room AC") -> First query the home list, then query room list to match "living room", then list devices in that room
   - If multiple devices match, list all candidates and ask the user to choose
2. **Get current state** — Call the "Get Single Device Detail" API. The `properties` field in the response contains the current values of each functional property (e.g. switch state, brightness level, temperature setting), which can be used to determine the device's current state
3. **Query capabilities** — With the device_id, call the "Query Device Thing Model" API to get the device's supported property list and understand each property's type and value range
4. **Map the command** — Map the user's intent to Thing Model properties:
   - Turn on/off -> Find a bool-type switch property (e.g. `switch_led`, `switch`)
   - Adjust brightness -> Find a value-type brightness property
   - Adjust temperature -> Find a value-type temp property
   - If the device does not support the requested function, inform the user
5. **Issue the command** — Call the "Issue Properties" API, assembling the property code and target value as a JSON string
6. **Return the result** — Inform the user whether the operation succeeded

### Workflow 2: Rename Device

1. Locate the device using Workflow 1 Step 1 to obtain the device_id
2. Call the "Rename Device" API with the new name
3. Return the result

### Workflow 3: Notifications

1. Identify the message type: SMS / Voice / Email / App Push
2. Extract required parameters (message content; email also needs a subject)
3. Call the corresponding API (all notification APIs are self-send — messages can only be sent to the current logged-in user)
4. Return the send result

### Workflow 4: Weather Query

1. Obtain the user's latitude and longitude (ask the user or infer from context)
2. Determine which weather attributes to query (default: temperature, humidity, weather condition)
3. Call the weather query API
4. Translate the returned data into a human-readable description

### Workflow 5: Data Statistics

1. Locate the device (same as Workflow 1 Step 1)
2. Call the "Statistics Config Query" API to confirm whether the device has the corresponding statistics capability
3. If available, call the "Statistics Value Query" API to get data for the specified time range
4. Aggregate and return the results

## API Calling Convention

### Request Format

All APIs use the configured Base URL concatenated with the path. Examples:

```
GET {base_url}/v1.0/end-user/homes/all
POST {base_url}/v1.0/end-user/devices/{device_id}/shadow/properties/issue
```

### Response Format

APIs return a unified structure:

**Success response**:
```json
{
  "success": true,
  "t": 1710234567890,
  "result": { ... }
}
```

**Error response**:
```json
{
  "success": false,
  "code": 1108,
  "msg": "uri path invalid"
}
```

- When `success` is `true`, the result is in the `result` field
- When `success` is `false`, error details are in the `code` and `msg` fields

### Error Handling

| Scenario | How to Handle |
|----------|--------------|
| Device not found | Tell the user: "Cannot find a device named XX, please verify the device name" |
| Device does not support the function | Tell the user: "Device XX does not support XX function", and list the device's supported functions |
| Home/room not found | Tell the user: "Cannot find a home/room named XX" |
| Multiple devices match | List all matching devices and ask the user to choose |
| Notification send failure | Return the specific error code explanation (rate limit, format error, etc.) |
| token invalid (code: 1010) | Tell the user the Api-key has expired and needs to be updated |
| uri path invalid (code: 1108) | Check whether the API path is correct |
| API call failure | Tell the user: "Service is temporarily unavailable, please try again later" |
| Other unresolvable issues | Guide the user to visit the GitHub repository for announcements and troubleshooting: https://github.com/tuya/tuya-openclaw-skills |

## Supported and Unsupported Operations

### Supported Property Types for Control

Only basic data type properties are currently supported for device control:

| Type | Description | Example |
|------|-------------|---------|
| bool | Boolean on/off | Turn light on/off, turn AC on/off, turn plug on/off |
| enum | Enumeration selection | Switch AC mode (auto/cold/hot), set fan speed (low/mid/high) |
| value (Integer) | Numeric value | Adjust brightness (0-1000), set temperature (16-30) |
| string | String value | Set device display text |

### Unsupported Operations

The following operations involve sensitive actions or complex data types and are **NOT supported**:

- **Lock control** — Unlock doors, lock/unlock smart locks (security-sensitive)
- **Video/camera operations** — Pull live video streams, view camera footage, capture screenshots
- **Image operations** — Retrieve or push images from/to devices
- **Complex data type control** — Properties with `raw`, `bitmap`, `struct`, or `array` typeSpec are not supported for issuing commands
- **Firmware upgrades** — OTA firmware update operations
- **Device pairing/removal** — Adding new devices or removing existing devices

If the user requests any of these unsupported operations, clearly inform them that the operation is not available through this skill and suggest using the Tuya App directly.

## Data Egress Statement

**This skill sends data to the Tuya Open Platform**:

| Data Type | Sent To | Purpose | Required |
|-----------|---------|---------|----------|
| Api-key | User-configured base_url | API authentication | Required |
| Device ID | User-configured base_url | Device query and control | Required |
| Control commands | User-configured base_url | Device property issuance | Required |

## Important Notes

1. Device name matching uses fuzzy matching; when multiple results are found, ask the user to confirm
2. When issuing properties, the `properties` field value is a **JSON string** (requires escaping), not a JSON object
3. The statistics API time format is `yyyyMMddHH`, and the time range cannot exceed 24 hours
4. All four notification APIs are self-send only — messages can only be sent to the currently logged-in user
5. The weather query requires latitude and longitude parameters; if the user does not provide them, ask for their city and convert to coordinates
6. Different regions use different base_url values — these are auto-detected from the API key prefix, but can be overridden with `TUYA_BASE_URL` if needed
7. If you encounter any issues during use, please visit the GitHub repository for the latest announcements and usage guides: https://github.com/tuya/tuya-openclaw-skills
