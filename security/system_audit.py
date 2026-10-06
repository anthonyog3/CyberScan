import subprocess
import json


def check_firewall():
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout.lower()

        if "state" in output and "on" in output:
            return {
                "name": "Windows Firewall",
                "status": "Secure",
                "score": 20,
                "details": "Windows Firewall appears to be enabled."
            }

        return {
            "name": "Windows Firewall",
            "status": "Warning",
            "score": 0,
            "details": "One or more firewall profiles may be disabled."
        }

    except Exception as e:
        return {
            "name": "Windows Firewall",
            "status": "Unknown",
            "score": 0,
            "details": f"Could not check firewall: {e}"
        }


def check_antivirus():
    try:
        command = (
            "Get-CimInstance -Namespace root/SecurityCenter2 "
            "-ClassName AntiVirusProduct | "
            "Select-Object displayName,productState | "
            "ConvertTo-Json -Compress"
        )

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0 or not result.stdout.strip():
            return {
                "name": "Antivirus Protection",
                "status": "Warning",
                "score": 0,
                "details": "No registered antivirus provider was detected."
            }

        data = json.loads(result.stdout.strip())

        # If Windows returns one antivirus as an object instead of a list
        if isinstance(data, dict):
            data = [data]

        antivirus_names = []

        for product in data:
            name = product.get("displayName")

            if name:
                antivirus_names.append(name)

        if antivirus_names:
            names = ", ".join(antivirus_names)

            return {
                "name": "Antivirus Protection",
                "status": "Secure",
                "score": 20,
                "details": f"Registered antivirus provider detected: {names}."
            }

        return {
            "name": "Antivirus Protection",
            "status": "Warning",
            "score": 0,
            "details": "No registered antivirus provider was detected."
        }

    except json.JSONDecodeError:
        return {
            "name": "Antivirus Protection",
            "status": "Unknown",
            "score": 0,
            "details": "Could not parse Windows antivirus information."
        }

    except Exception as e:
        return {
            "name": "Antivirus Protection",
            "status": "Unknown",
            "score": 0,
            "details": f"Could not check antivirus status: {e}"
        }

def check_windows_update():
    try:
        command = (
            "Get-CimInstance Win32_Service -Filter \"Name='wuauserv'\" | "
            "Select-Object State,StartMode,Name | "
            "ConvertTo-Json -Compress"
        )

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0 or not result.stdout.strip():
            return {
                "name": "Windows Update",
                "status": "Unknown",
                "score": 0,
                "details": "Could not retrieve Windows Update information."
            }

        data = json.loads(result.stdout.strip())

        state = str(data.get("State", "")).lower()
        start_mode = str(data.get("StartMode", "")).lower()

        # Automatic startup
        if start_mode == "auto":
            return {
                "name": "Windows Update",
                "status": "Secure",
                "score": 20,
                "details": f"Windows Update is configured to start automatically. Current status: {state}."
            }

        # Manual startup is also normal for some Windows configurations
        if start_mode == "manual":
            return {
                "name": "Windows Update",
                "status": "Secure",
                "score": 20,
                "details": f"Windows Update is configured for manual startup. Current status: {state}."
            }

        return {
            "name": "Windows Update",
            "status": "Warning",
            "score": 0,
            "details": f"Windows Update startup mode is '{start_mode}'."
        }

    except json.JSONDecodeError:
        return {
            "name": "Windows Update",
            "status": "Unknown",
            "score": 0,
            "details": "Could not parse Windows Update information."
        }

    except Exception as e:
        return {
            "name": "Windows Update",
            "status": "Unknown",
            "score": 0,
            "details": f"Could not check Windows Update: {e}"
        }
    
def check_user_account_security():
    try:
        command = (
            "Get-LocalUser | "
            "Where-Object {$_.Enabled -eq $true} | "
            "Select-Object Name,Enabled | "
            "ConvertTo-Json -Compress"
        )

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0 or not result.stdout.strip():
            return {
                "name": "User Account Security",
                "status": "Unknown",
                "score": 0,
                "details": "Could not retrieve local user account information."
            }

        data = json.loads(result.stdout.strip())

        if isinstance(data, dict):
            data = [data]

        enabled_users = [
            user.get("Name")
            for user in data
            if user.get("Name")
        ]

        return {
            "name": "User Account Security",
            "status": "Secure",
            "score": 20,
            "details": f"{len(enabled_users)} enabled local user account(s) detected. Account count alone is not considered a security issue."
        }

    except json.JSONDecodeError:
        return {
            "name": "User Account Security",
            "status": "Unknown",
            "score": 0,
            "details": "Could not parse user account information."
        }

    except Exception as e:
        return {
            "name": "User Account Security",
            "status": "Unknown",
            "score": 0,
            "details": f"Could not check user accounts: {e}"
        }    
def check_security_configuration():
    try:
        command = (
            "Get-ItemProperty "
            "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name EnableLUA | "
            "Select-Object EnableLUA | "
            "ConvertTo-Json -Compress"
        )

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0 or not result.stdout.strip():
            return {
                "name": "Security Configuration",
                "status": "Unknown",
                "score": 0,
                "details": "Could not retrieve Windows security configuration."
            }

        data = json.loads(result.stdout.strip())

        uac_enabled = data.get("EnableLUA", 0)

        if int(uac_enabled) == 1:
            return {
                "name": "Security Configuration",
                "status": "Secure",
                "score": 20,
                "details": "User Account Control (UAC) is enabled."
            }

        return {
            "name": "Security Configuration",
            "status": "Warning",
            "score": 0,
            "details": "User Account Control (UAC) appears to be disabled."
        }

    except json.JSONDecodeError:
        return {
            "name": "Security Configuration",
            "status": "Unknown",
            "score": 0,
            "details": "Could not parse Windows security configuration."
        }

    except Exception as e:
        return {
            "name": "Security Configuration",
            "status": "Unknown",
            "score": 0,
            "details": f"Could not check security configuration: {e}"
        }


def run_security_audit():
    checks = [
        check_firewall(),
        check_antivirus(),
        check_windows_update(),
        check_user_account_security(),
        check_security_configuration()
    ]

    total_score = sum(
        check.get("score", 0)
        for check in checks
    )

    return {
        "score": total_score,
        "checks": checks
    }


if __name__ == "__main__":
    result = run_security_audit()

    print("=" * 40)
    print("       CYBERSCAN SECURITY AUDIT")
    print("=" * 40)

    print(f"\nSecurity Score: {result['score']}/100\n")

    for check in result["checks"]:
        print(f"{check['name']}")
        print(f"Status: {check['status']}")
        print(f"Details: {check['details']}")
        print("-" * 40)