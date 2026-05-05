import pandas as pd
import numpy as np
from pathlib import Path
import joblib
import shutil
import ctypes
from datetime import datetime
import sys
import subprocess
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


FEATURE_COLUMNS = [
    "file_write_count_60s",
    "file_rename_count_60s",
    "modified_file_count_60s",
    "avg_entropy_60s",
    "avg_entropy_change_60s",
    "smb_connection_count_60s",
    "ransom_note_created",
    "suspicious_process_path",
    "security_process_killed"
]


def load_models(model_folder):
    """
    Đọc mô hình Random Forest và Isolation Forest đã huấn luyện.
    """

    model_folder = Path(model_folder)

    rf_path = model_folder / "random_forest_model.pkl"
    iso_path = model_folder / "isolation_forest_model.pkl"

    rf_model = None

    if rf_path.exists():
        rf_model = joblib.load(rf_path)
    else:
        print("[WARNING] Không tìm thấy random_forest_model.pkl")

    if not iso_path.exists():
        raise FileNotFoundError("Không tìm thấy isolation_forest_model.pkl")

    iso_model = joblib.load(iso_path)

    return rf_model, iso_model


def load_feature_file(input_file):
    """
    Đọc file đặc trưng cần nhận diện.
    """

    df = pd.read_csv(input_file)

    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0

        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    return df


def normalize_if_scores(raw_scores):
    """
    Chuyển điểm Isolation Forest thành IF_score từ 0 đến 1.
    """

    anomaly_scores = -raw_scores

    min_score = anomaly_scores.min()
    max_score = anomaly_scores.max()

    if max_score - min_score == 0:
        return np.zeros_like(anomaly_scores)

    return (anomaly_scores - min_score) / (max_score - min_score)


def calculate_rule_score(row):
    """
    Tính Rule Score dựa trên các dấu hiệu mạnh của ransomware.
    """

    score = 0.0

    if row["ransom_note_created"] == 1:
        score += 0.4

    if row["security_process_killed"] == 1:
        score += 0.3

    if row["file_rename_count_60s"] > 20:
        score += 0.1

    if row["suspicious_process_path"] == 1:
        score += 0.1

    if row["smb_connection_count_60s"] > 10:
        score += 0.1

    if row["avg_entropy_change_60s"] > 2.0:
        score += 0.1

    return min(score, 1.0)


def classify_risk(risk_score):
    """
    Phân loại mức cảnh báo.
    """

    if risk_score >= 0.81:
        return "Ransomware / LockerGoga-like"
    elif risk_score >= 0.61:
        return "Nguy cơ cao"
    elif risk_score >= 0.31:
        return "Nghi ngờ"
    else:
        return "Bình thường"

def recommend_action(alert_level):
    """
    Đề xuất hành động phản ứng dựa trên mức cảnh báo.
    """

    if alert_level == "Bình thường":
        return "Không cảnh báo, chỉ ghi log"

    elif alert_level == "Nghi ngờ":
        return "Gửi cảnh báo cho quản trị viên"

    elif alert_level == "Nguy cơ cao":
        return "Cảnh báo, theo dõi tiến trình, hạn chế truy cập nếu cần"

    elif alert_level == "Ransomware / LockerGoga-like":
        return "Cảnh báo khẩn cấp, dừng tiến trình nghi ngờ, cách ly file, khóa SMB tạm thời"

    else:
        return "Không xác định"

def quarantine_file(file_path, quarantine_dir=r"C:\AI\Quarantine"):
    """
    Đưa file nghi ngờ vào thư mục quarantine.
    Không xóa file, chỉ di chuyển và đổi tên để tránh chạy lại.
    """

    try:
        file_path = Path(str(file_path))

        if not file_path.exists() or not file_path.is_file():
            return "Không tìm thấy file để cách ly"

        quarantine_dir = Path(quarantine_dir)
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        new_name = f"{file_path.name}.{timestamp}.quarantined"
        destination = quarantine_dir / new_name

        shutil.move(str(file_path), str(destination))

        return f"Đã cách ly file: {destination}"

    except Exception as e:
        return f"Lỗi khi cách ly file: {e}"

def generate_alert_reason(row):
    """
    Tạo lý do cảnh báo dựa trên các đặc trưng nguy hiểm.
    """

    reasons = []

    if row["file_write_count_60s"] > 100:
        reasons.append("Ghi nhiều file trong 60 giây")

    if row["file_rename_count_60s"] > 20:
        reasons.append("Đổi tên nhiều file trong 60 giây")

    if row["avg_entropy_change_60s"] > 2.0:
        reasons.append("Entropy tăng cao, có dấu hiệu dữ liệu bị mã hóa")

    if row["smb_connection_count_60s"] > 10:
        reasons.append("Có nhiều kết nối SMB bất thường")

    if row["ransom_note_created"] == 1:
        reasons.append("Phát hiện file có dấu hiệu ransom note")

    if row["suspicious_process_path"] == 1:
        reasons.append("Tiến trình chạy từ đường dẫn đáng ngờ")

    if row["security_process_killed"] == 1:
        reasons.append("Có dấu hiệu tác động đến tiến trình bảo mật")

    if not reasons:
        return "Không có dấu hiệu nguy hiểm rõ ràng"

    return "; ".join(reasons)


def auto_response(row):
    """
    Tự động phản ứng dựa trên Risk Score.
    """

    risk_score = row["Risk_score"]
    alert_level = row["alert_level"]

    # Bình thường: không làm gì
    if alert_level == "Bình thường":
        return "Không cảnh báo, không phản ứng"

    # Nghi ngờ: chỉ cảnh báo
    if alert_level == "Nghi ngờ":
        return "Đã ghi nhận cảnh báo nghi ngờ"

    # Nguy cơ cao: hạn chế, chưa quarantine
    if alert_level == "Nguy cơ cao":
        return "Cảnh báo nguy cơ cao, cần kiểm tra tiến trình"

    # Ransomware: quarantine nếu có process_group rõ ràng
    if alert_level == "Ransomware / LockerGoga-like":
        process_path = row.get("process_group", "")

        if process_path and process_path != "unknown_process":
            return quarantine_file(process_path)

        return "Cảnh báo ransomware nhưng không có đường dẫn file rõ ràng để cách ly"

    return "Không xác định hành động"

def has_ransomware_alert(results):
    """
    Kiem tra co canh bao muc Ransomware / LockerGoga-like hay khong.
    """

    return (
        results["alert_level"] == "Ransomware / LockerGoga-like"
    ).any()

def detect_samples(input_file, model_folder, output_file):
    """
    Nhận diện các mẫu hành vi mới.
    """

    rf_model, iso_model = load_models(model_folder)
    df = load_feature_file(input_file)

    X = df[FEATURE_COLUMNS]

    if rf_model is not None:
        rf_scores = rf_model.predict_proba(X)[:, 1]
    else:
        rf_scores = np.zeros(len(df))

    raw_if_scores = iso_model.decision_function(X)
    if_scores = normalize_if_scores(raw_if_scores)

    results = df.copy()

    results["RF_score"] = rf_scores
    results["IF_score"] = if_scores
    results["Rule_score"] = results.apply(calculate_rule_score, axis=1)

    results["Risk_score"] = (
        0.5 * results["RF_score"] +
        0.3 * results["IF_score"] +
        0.2 * results["Rule_score"]
    )

    results["alert_level"] = results["Risk_score"].apply(classify_risk)
    results["alert_reason"] = results.apply(generate_alert_reason, axis=1)
    results["recommended_action"] = results["alert_level"].apply(recommend_action)
    results["auto_response_result"] = results.apply(auto_response, axis=1)

    results.to_csv(output_file, index=False, encoding="utf-8-sig")
    save_alert_file(results, output_file)
    print_alerts(results)

    print("Đã nhận diện xong.")
    print("File đầu vào:", input_file)
    print("File kết quả:", output_file)

    columns_to_show = [
        "time_window",
        "process_group",
        "file_write_count_60s",
        "file_rename_count_60s",
        "avg_entropy_60s",
        "avg_entropy_change_60s",
        "smb_connection_count_60s",
        "ransom_note_created",
        "suspicious_process_path",
        "security_process_killed",
        "RF_score",
        "IF_score",
        "Rule_score",
        "Risk_score",
        "alert_level"
    ]

    available_columns = [col for col in columns_to_show if col in results.columns]

    print("\n=== KẾT QUẢ NHẬN DIỆN ===")
    print(results[available_columns].head(30))
    if has_ransomware_alert(results):
        print("[CRITICAL] Phat hien Ransomware / LockerGoga-like. Dung realtime monitor.")
        return 2

    return 0

def show_windows_popup(message, title="AI Ransomware Detection"):
    """
    Hien thi popup canh bao nhung khong chan chuong trinh.
    Popup chay bang powershell rieng nen detect_new_sample.py van co the ket thuc.
    """

    try:
        safe_message = str(message).replace("'", "''")
        safe_title = str(title).replace("'", "''")

        command = (
            "Add-Type -AssemblyName PresentationFramework; "
            f"[System.Windows.MessageBox]::Show('{safe_message}', '{safe_title}')"
        )

        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command", command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    except Exception:
        pass

def save_alert_file(results, output_file):
    """
    Lưu riêng các dòng có cảnh báo.
    """

    alert_rows = results[results["alert_level"] != "Bình thường"].copy()

    alert_file = str(output_file).replace(".csv", "_alerts.csv")

    alert_rows.to_csv(alert_file, index=False, encoding="utf-8-sig")

    print("Đã lưu file cảnh báo:", alert_file)


def print_alerts(results):
    """
    In cảnh báo ra màn hình.
    Chỉ in các mẫu không phải Bình thường.
    """

    alert_rows = results[results["alert_level"] != "Bình thường"]

    if alert_rows.empty:
        print("\nKhông phát hiện cảnh báo nguy hiểm.")
        return

    print("\n=== DANH SÁCH CẢNH BÁO ===")

    for _, row in alert_rows.iterrows():
        print("\n------------------------------")
        print("CẢNH BÁO:", row["alert_level"])
        print("Thời gian:", row.get("time_window", "N/A"))
        print("Tiến trình:", row.get("process_group", "N/A"))
        print("Risk Score:", round(row["Risk_score"], 3))
        print("RF Score:", round(row["RF_score"], 3))
        print("IF Score:", round(row["IF_score"], 3))
        print("Rule Score:", round(row["Rule_score"], 3))
        print("Lý do:", row["alert_reason"])
        print("Hành động đề xuất:", row["recommended_action"])

        if row["alert_level"] == "Ransomware / LockerGoga-like":
            show_windows_popup(
        f"Phat hien hanh vi giong LockerGoga!\n"
        f"Risk Score: {round(row['Risk_score'], 3)}\n"
        f"Tien trinh: {row.get('process_group', 'N/A')}",
        "CANH BAO RANSOMWARE"
    )
 

if __name__ == "__main__":
    exit_code = detect_samples(
        input_file=r"C:\AI\LogExport\features_dataset.csv",
        model_folder=r"C:\AI\LogExport\ModelOutput",
        output_file=r"C:\AI\LogExport\ModelOutput\new_detection_results.csv"
    )
    sys.exit(exit_code)