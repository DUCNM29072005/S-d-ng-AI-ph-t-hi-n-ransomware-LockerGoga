import time
import subprocess
from datetime import datetime
from pathlib import Path


PYTHON_EXE = "python"

BASE_DIR = Path(r"src")

COLLECT_SCRIPT = BASE_DIR / "Buoc1_log_collection.py"
PREPROCESS_SCRIPT = BASE_DIR / "Buoc2_preprocess_data.py"
EXTRACT_SCRIPT = BASE_DIR / "Buoc3_extract_features.py"
DETECT_SCRIPT = BASE_DIR / "Buoc6_detect_new_sample.py"

MONITOR_INTERVAL = 60  # số giây giữa mỗi lần quét

def run_script(script_path):
    """
    Chạy một file Python và trả về trạng thái thành công/thất bại.
    """

    try:
        print(f"\n[RUN] {script_path.name}")

        result = subprocess.run(
            [PYTHON_EXE, str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        if result.stdout:
            print(result.stdout)

        if result.stderr:
            print("[ERROR OUTPUT]")
            print(result.stderr)

        return result.returncode == 0

    except Exception as e:
        print(f"[ERROR] Khong chay duoc {script_path.name}: {e}")
        return False

def monitor_loop():
    """
    Vong lap giam sat lien tuc.
    """

    print("======================================")
    print("AI Ransomware Detection Monitor")
    print("Che do: Giam sat lien tuc")
    print("Khoang thoi gian quet:", MONITOR_INTERVAL, "giay")
    print("Neu phat hien ransomware, chuong trinh se canh bao va dung quet.")
    print("Nhan Ctrl + C de dung thu cong")
    print("======================================")

    while True:
        print("\n--------------------------------------")
        print("[TIME]", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("[INFO] Bat dau mot vong quet moi")

        collect_code = run_script(COLLECT_SCRIPT)

        if not collect_code:
            print("[WARNING] Buoc thu thap log that bai, bo qua vong nay.")
            time.sleep(MONITOR_INTERVAL)
            continue

        preprocess_code = run_script(PREPROCESS_SCRIPT)

        if not preprocess_code:
            print("[WARNING] Buoc tien xu ly that bai, bo qua vong nay.")
            time.sleep(MONITOR_INTERVAL)
            continue

        extract_code = run_script(EXTRACT_SCRIPT)

        if not extract_code:
            print("[WARNING] Buoc trich xuat dac trung that bai, bo qua vong nay.")
            time.sleep(MONITOR_INTERVAL)
            continue

        detect_code = run_script(DETECT_SCRIPT)

        if detect_code == 2:
            print("[CRITICAL] AI phat hien Ransomware / LockerGoga-like.")
            print("[STOP] Dung giam sat lien tuc de xu ly su co.")
            break

        if detect_code != 0:
            print("[WARNING] Buoc nhan dien that bai.")

        print("[INFO] Hoan thanh vong quet.")
        print(f"[INFO] Cho {MONITOR_INTERVAL} giay truoc vong tiep theo...")

        time.sleep(MONITOR_INTERVAL)
if __name__ == "__main__":
    try:
        monitor_loop()
    except KeyboardInterrupt:
        print("\n[STOP] Đã dừng giám sát liên tục.")
