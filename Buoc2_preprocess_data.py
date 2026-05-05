import pandas as pd
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

def normalize_columns(df):
    """
    Chuẩn hóa tên cột.
    """

    df = df.copy()

    df.columns = [col.strip() for col in df.columns]

    rename_map = {
        "TimeCreated": "time_created",
        "Id": "event_id",
        "ProviderName": "provider_name",
        "Message": "message"
    }

    df = df.rename(columns=rename_map)

    required_columns = [
        "time_created",
        "event_id",
        "provider_name",
        "message",
        "source"
    ]

    for col in required_columns:
        if col not in df.columns:
            df[col] = None

    return df


def normalize_data_types(df):
    """
    Chuẩn hóa kiểu dữ liệu.
    """

    df = df.copy()

    df["time_created"] = pd.to_datetime(
        df["time_created"],
        errors="coerce"
    )

    df["event_id"] = pd.to_numeric(
        df["event_id"],
        errors="coerce"
    )

    df["message"] = df["message"].fillna("").astype(str)
    df["source"] = df["source"].fillna("").astype(str)

    return df


def clean_logs(df):
    """
    Làm sạch dữ liệu:
    - Loại bỏ log thiếu thời gian
    - Loại bỏ log thiếu event_id
    - Loại bỏ bản ghi trùng lặp
    - Sắp xếp theo thời gian
    """

    df = df.copy()

    before = len(df)

    df = df.dropna(subset=["time_created", "event_id"])

    df = df.drop_duplicates(
        subset=["time_created", "event_id", "source", "message"]
    )

    df = df.sort_values("time_created").reset_index(drop=True)

    after = len(df)

    print("Số dòng trước làm sạch:", before)
    print("Số dòng sau làm sạch:", after)
    print("Số dòng bị loại:", before - after)

    return df


def extract_field(message, field_name):
    """
    Trích xuất giá trị field trong cột message.
    Ví dụ: Image, TargetFilename, DestinationIp, DestinationPort.
    """

    pattern = rf"{field_name}:\s*(.*)"
    match = re.search(pattern, str(message), re.IGNORECASE)

    if match:
        return match.group(1).split("\n")[0].strip()

    return ""


def parse_message_fields(df):
    """
    Tách các trường quan trọng từ cột message.
    """

    df = df.copy()

    df["process_path"] = df["message"].apply(
        lambda x: extract_field(x, "Image")
    )

    df["command_line"] = df["message"].apply(
        lambda x: extract_field(x, "CommandLine")
    )

    df["target_file"] = df["message"].apply(
        lambda x: extract_field(x, "TargetFilename")
    )

    df["destination_ip"] = df["message"].apply(
        lambda x: extract_field(x, "DestinationIp")
    )

    df["destination_port"] = df["message"].apply(
        lambda x: extract_field(x, "DestinationPort")
    )

    df["user"] = df["message"].apply(
        lambda x: extract_field(x, "User")
    )

    return df


def normalize_paths(df):
    """
    Chuẩn hóa đường dẫn process, file và command line.
    """

    df = df.copy()

    for col in ["process_path", "target_file", "command_line"]:
        df[col] = df[col].fillna("").astype(str).str.strip().str.lower()

    return df


def is_suspicious_path(path):
    """
    Xác định tiến trình có chạy từ vị trí đáng ngờ hay không.
    """

    if not isinstance(path, str):
        return 0

    path = path.lower()

    suspicious_keywords = [
        "appdata",
        "temp",
        "users\\public",
        "downloads",
        "programdata"
    ]

    return int(any(keyword in path for keyword in suspicious_keywords))


def is_smb_connection(row):
    """
    Xác định event có liên quan SMB hay không.
    SMB thường dùng port 445.
    """

    port = str(row.get("destination_port", "")).strip()

    if port == "445":
        return 1

    message = str(row.get("message", "")).lower()

    if "smb" in message:
        return 1

    return 0


def is_ransom_note(path):
    """
    Nhận diện tên file giống ransom note.
    """

    path = str(path).lower()

    keywords = [
        "readme",
        "decrypt",
        "recover",
        "restore",
        "ransom",
        "how_to"
    ]

    return int(any(keyword in path for keyword in keywords))


def security_process_indicator(message):
    """
    Đánh dấu event có liên quan tiến trình hoặc dịch vụ bảo mật.
    """

    message = str(message).lower()

    security_keywords = [
        "windefend",
        "defender",
        "security center",
        "antivirus",
        "msmpeng",
        "sense"
    ]

    return int(any(keyword in message for keyword in security_keywords))


def preprocess_logs(input_file, output_file):
    """
    Đọc raw_logs.csv, tiền xử lý và lưu preprocessed_logs.csv.
    """

    df = pd.read_csv(input_file)

    print("Đã đọc dữ liệu thô:", input_file)
    print("Số dòng ban đầu:", len(df))

    df = normalize_columns(df)
    df = normalize_data_types(df)
    df = clean_logs(df)
    df = parse_message_fields(df)
    df = normalize_paths(df)

    df["suspicious_process_path"] = df["process_path"].apply(
        is_suspicious_path
    )

    df["is_smb_connection"] = df.apply(
        is_smb_connection,
        axis=1
    )

    df["ransom_note_created"] = df["target_file"].apply(
        is_ransom_note
    )

    df["security_process_related"] = df["message"].apply(
        security_process_indicator
    )

    df.to_csv(output_file, index=False, encoding="utf-8-sig")

    print(f"\nĐã lưu dữ liệu tiền xử lý tại: {output_file}")
    print("Số dòng sau tiền xử lý:", len(df))


if __name__ == "__main__":
    preprocess_logs(
        input_file=r"LogExport\raw_logs.csv",
        output_file=r"LogExport\preprocessed_logs.csv"
    )
