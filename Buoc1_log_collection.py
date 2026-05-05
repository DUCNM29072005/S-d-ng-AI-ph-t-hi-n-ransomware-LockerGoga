import pandas as pd
from pathlib import Path
import subprocess
import sys
import warnings

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

warnings.filterwarnings("ignore", category=UserWarning)


LOG_DIR = Path(r"LogExport")


def export_windows_logs():
    """
    Export log moi nhat tu Windows Event Viewer ra cac file CSV.
    Ham nay duoc goi moi lan log_collection.py chay.
    """

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    ps_script = rf"""
$LogDir = "{LOG_DIR}"

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\sysmon_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Security" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\security_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "System" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\system_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Application" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\application_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\defender_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\powershell_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\powershell_operational_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-SMBClient/Connectivity" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\smbclient_connectivity_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-SMBClient/Security" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\smbclient_security_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-SMBServer/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\smbserver_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\taskscheduler_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\wmi_activity_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\rdp_localsession_logs.csv" -NoTypeInformation -Encoding UTF8

Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv "$LogDir\rdp_remoteconnection_logs.csv" -NoTypeInformation -Encoding UTF8
"""

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_script
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        print("[WARNING] Export log co loi:")
        print(result.stderr)
        return False

    print("[OK] Da export log moi nhat ra CSV")
    return True


def collect_logs(log_folder, output_file):
    """
    Export log moi nhat, doc cac file CSV, bo qua file loi/rong,
    gop lai thanh raw_logs.csv.
    """

    export_windows_logs()

    log_folder = Path(log_folder)
    log_folder.mkdir(parents=True, exist_ok=True)

    log_files = {
        "sysmon": "sysmon_logs.csv",
        "security": "security_logs.csv",
        "system": "system_logs.csv",
        "application": "application_logs.csv",
        "defender": "defender_logs.csv",
        "powershell": "powershell_logs.csv",
        "powershell_operational": "powershell_operational_logs.csv",
        "smbclient_connectivity": "smbclient_connectivity_logs.csv",
        "smbclient_security": "smbclient_security_logs.csv",
        "smbserver": "smbserver_logs.csv",
        "taskscheduler": "taskscheduler_logs.csv",
        "wmi": "wmi_activity_logs.csv",
        "rdp_local": "rdp_localsession_logs.csv",
        "rdp_remote": "rdp_remoteconnection_logs.csv"
    }

    all_logs = []

    for source, filename in log_files.items():
        file_path = log_folder / filename

        if not file_path.exists():
            print(f"[MISS] Khong tim thay file: {file_path}")
            continue

        if file_path.stat().st_size == 0:
            print(f"[SKIP] File rong: {file_path}")
            continue

        try:
            df = pd.read_csv(file_path, encoding="utf-8-sig")

            if df.empty:
                print(f"[SKIP] File khong co du lieu: {file_path}")
                continue

            required_columns = ["TimeCreated", "Id", "ProviderName", "Message"]

            for col in required_columns:
                if col not in df.columns:
                    df[col] = None

            df = df[required_columns]
            df["source"] = source

            all_logs.append(df)

            print(f"[OK] Da doc {filename}: {len(df)} dong")

        except pd.errors.EmptyDataError:
            print(f"[SKIP] File CSV rong/khong co cot: {file_path}")

        except Exception as e:
            print(f"[ERROR] Loi khi doc {file_path}: {e}")

    if not all_logs:
        print("Khong co file log nao doc duoc.")
        return 1

    raw_logs = pd.concat(all_logs, ignore_index=True)

    raw_logs["TimeCreated"] = pd.to_datetime(
        raw_logs["TimeCreated"],
        errors="coerce"
    )

    raw_logs["Id"] = pd.to_numeric(
        raw_logs["Id"],
        errors="coerce"
    )

    raw_logs = raw_logs.dropna(subset=["TimeCreated", "Id"])
    raw_logs = raw_logs.sort_values("TimeCreated").reset_index(drop=True)

    raw_logs.to_csv(output_file, index=False, encoding="utf-8-sig")

    print(f"\nDa luu du lieu tho tai: {output_file}")
    print(f"Tong so dong log: {len(raw_logs)}")

    print("\n5 dong dau tien:")
    print(raw_logs.head())

    print("\nThong ke so dong theo nguon log:")
    print(raw_logs["source"].value_counts())

    return 0


if __name__ == "__main__":
    exit_code = collect_logs(
        log_folder=r"LogExport",
        output_file=r"raw_logs.csv"
    )

    sys.exit(exit_code)
