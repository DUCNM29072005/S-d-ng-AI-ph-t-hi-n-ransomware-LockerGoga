import pandas as pd
from pathlib import Path
import math
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def load_preprocessed_logs(input_file):
    """
    Đọc dữ liệu đã tiền xử lý từ preprocessed_logs.csv.
    """

    df = pd.read_csv(input_file)

    if "time_created" not in df.columns:
        raise ValueError("Thiếu cột time_created trong dữ liệu.")

    df["time_created"] = pd.to_datetime(
        df["time_created"],
        errors="coerce"
    )

    df = df.dropna(subset=["time_created"])

    return df


def prepare_base_columns(df):
    """
    Đảm bảo các cột cần thiết tồn tại.
    Nếu thiếu thì tạo cột mặc định.
    """

    df = df.copy()

    required_columns = {
        "process_path": "",
        "target_file": "",
        "event_id": 0,
        "is_smb_connection": 0,
        "ransom_note_created": 0,
        "suspicious_process_path": 0,
        "security_process_related": 0,
        "source": "",
        "message": ""
    }

    for col, default_value in required_columns.items():
        if col not in df.columns:
            df[col] = default_value

    df["process_path"] = df["process_path"].fillna("").astype(str)
    df["target_file"] = df["target_file"].fillna("").astype(str)
    df["message"] = df["message"].fillna("").astype(str)

    df["event_id"] = pd.to_numeric(
        df["event_id"],
        errors="coerce"
    ).fillna(0).astype(int)

    for col in [
        "is_smb_connection",
        "ransom_note_created",
        "suspicious_process_path",
        "security_process_related"
    ]:
        df[col] = pd.to_numeric(
            df[col],
            errors="coerce"
        ).fillna(0).astype(int)

    return df


def load_simulation_events(sim_file=r"C:\AI\LogExport\simulation_events.csv"):
    """
    Đọc log mô phỏng nếu có.
    File này được tạo bởi simulate_lockergoga_like.ps1.

    Các cột cần có:
    - time_created
    - process_path
    - target_file
    - event_type
    """

    sim_path = Path(sim_file)

    if not sim_path.exists():
        print("[INFO] Khong tim thay simulation_events.csv, bo qua log mo phong.")
        return pd.DataFrame()

    try:
        sim_df = pd.read_csv(sim_path, encoding="utf-8-sig")
    except Exception as e:
        print(f"[WARNING] Khong doc duoc simulation_events.csv: {e}")
        return pd.DataFrame()

    required_cols = [
        "time_created",
        "process_path",
        "target_file",
        "event_type"
    ]

    for col in required_cols:
        if col not in sim_df.columns:
            sim_df[col] = ""

    sim_df["time_created"] = pd.to_datetime(
        sim_df["time_created"],
        errors="coerce"
    )

    sim_df = sim_df.dropna(subset=["time_created"])

    sim_df["process_path"] = (
        sim_df["process_path"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    sim_df["target_file"] = (
        sim_df["target_file"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    sim_df["event_type"] = (
        sim_df["event_type"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    # Chuyển log mô phỏng về format giống preprocessed_logs.csv
    sim_df["event_id"] = 9999
    sim_df["is_smb_connection"] = 0

    sim_df["ransom_note_created"] = sim_df["event_type"].apply(
        lambda x: 1 if x == "ransom_note" else 0
    )

    sim_df["suspicious_process_path"] = 1
    sim_df["security_process_related"] = 0
    sim_df["source"] = "simulation"
    sim_df["message"] = sim_df["event_type"]

    print("[OK] Da doc simulation_events.csv:", len(sim_df), "dong")

    return sim_df


def calculate_file_entropy(file_path):
    """
    Tính Shannon entropy của một file theo byte.
    Entropy thường nằm trong khoảng 0-8.

    Nếu file không tồn tại, không phải file, hoặc không đọc được,
    hàm trả về None.
    """

    try:
        file_path = Path(str(file_path))

        if not file_path.exists() or not file_path.is_file():
            return None

        data = file_path.read_bytes()

        if len(data) == 0:
            return 0.0

        byte_counts = [0] * 256

        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count == 0:
                continue

            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    except Exception:
        return None


def add_file_entropy_column(df):
    """
    Tính entropy cho các file xuất hiện trong cột target_file.
    Nếu file không còn tồn tại hoặc không đọc được thì file_entropy = None.
    """

    df = df.copy()

    if "target_file" not in df.columns:
        df["file_entropy"] = None
        return df

    df["file_entropy"] = df["target_file"].apply(calculate_file_entropy)

    return df


def add_time_window(df, window="60s"):
    """
    Gom log theo cửa sổ thời gian.
    """

    df = df.copy()
    df["time_window"] = df["time_created"].dt.floor(window)
    return df


def normalize_process_group(df):
    """
    Nếu process_path rỗng, gán thành unknown_process để vẫn gom nhóm được.
    """

    df = df.copy()

    df["process_group"] = df["process_path"].replace("", "unknown_process")
    df["process_group"] = df["process_group"].fillna("unknown_process")

    return df


def extract_file_write_count(df):
    """
    Trích xuất số lượng file được tạo/ghi trong 60 giây.

    Nguồn tính:
    - Sysmon Event ID 11
    - target_file khác rỗng
    - simulation event: file_write, file_modify, high_entropy_file, ransom_note
    """

    message = df["message"].astype(str).str.lower()

    file_events = df[
        (df["event_id"] == 11) |
        (df["target_file"].astype(str).str.len() > 0) |
        (
            message.isin([
                "file_write",
                "file_modify",
                "high_entropy_file",
                "ransom_note"
            ])
        )
    ].copy()

    feature = (
        file_events
        .groupby(["time_window", "process_group"])
        .size()
        .reset_index(name="file_write_count_60s")
    )

    return feature


def extract_smb_connection_count(df):
    """
    Trích xuất số lượng kết nối SMB trong 60 giây.
    SMB thường liên quan đến port 445 hoặc cột is_smb_connection = 1.
    """

    smb_events = df[df["is_smb_connection"] == 1].copy()

    feature = (
        smb_events
        .groupby(["time_window", "process_group"])
        .size()
        .reset_index(name="smb_connection_count_60s")
    )

    return feature


def extract_ransom_note_feature(df):
    """
    Trích xuất đặc trưng ransom_note_created.
    Nếu trong cửa sổ thời gian có ít nhất một file giống ransom note thì giá trị = 1.
    """

    feature = (
        df.groupby(["time_window", "process_group"])["ransom_note_created"]
        .max()
        .reset_index()
    )

    return feature


def extract_suspicious_path_feature(df):
    """
    Trích xuất đặc trưng suspicious_process_path.
    Nếu tiến trình thuộc đường dẫn đáng ngờ thì giá trị = 1.
    """

    feature = (
        df.groupby(["time_window", "process_group"])["suspicious_process_path"]
        .max()
        .reset_index()
    )

    return feature


def extract_security_related_feature(df):
    """
    Trích xuất đặc trưng liên quan bảo mật.
    Trong mô phỏng, security_process_related được dùng gần với security_process_killed.
    """

    feature = (
        df.groupby(["time_window", "process_group"])["security_process_related"]
        .max()
        .reset_index(name="security_process_killed")
    )

    return feature


def extract_file_rename_count(df):
    """
    Trích xuất số file bị đổi tên.

    Nguồn tính:
    - target_file có .locked_test
    - target_file có renamed
    - simulation event/message = file_rename
    """

    target = df["target_file"].astype(str).str.lower()
    message = df["message"].astype(str).str.lower()

    rename_events = df[
        target.str.contains(".locked_test", regex=False) |
        target.str.contains("renamed", regex=False) |
        message.str.contains("file_rename", regex=False)
    ].copy()

    feature = (
        rename_events
        .groupby(["time_window", "process_group"])
        .size()
        .reset_index(name="file_rename_count_60s")
    )

    return feature


def extract_entropy_feature(df):
    """
    Trích xuất entropy trung bình của các file theo time_window và process_group.

    file_entropy được tính từ nội dung file thật ở cột target_file.
    Nếu file không còn tồn tại thì không được tính vào trung bình.
    """

    if "file_entropy" not in df.columns:
        return pd.DataFrame(
            columns=["time_window", "process_group", "avg_entropy_60s"]
        )

    entropy_events = df.dropna(subset=["file_entropy"]).copy()

    if entropy_events.empty:
        return pd.DataFrame(
            columns=["time_window", "process_group", "avg_entropy_60s"]
        )

    feature = (
        entropy_events
        .groupby(["time_window", "process_group"])["file_entropy"]
        .mean()
        .reset_index(name="avg_entropy_60s")
    )

    return feature


def merge_features(feature_frames):
    """
    Gộp các bảng đặc trưng lại với nhau.
    """

    if not feature_frames:
        raise ValueError("Không có feature frame nào để gộp.")

    features = feature_frames[0]

    for frame in feature_frames[1:]:
        features = pd.merge(
            features,
            frame,
            on=["time_window", "process_group"],
            how="outer"
        )

    features = features.fillna(0)

    return features


def add_derived_features(features):
    """
    Tạo thêm các đặc trưng suy diễn:
    - modified_file_count_60s: tạm lấy bằng file_write_count_60s
    - avg_entropy_60s: entropy trung bình, nếu không tính được thì gán 0
    """

    features = features.copy()

    if "file_write_count_60s" not in features.columns:
        features["file_write_count_60s"] = 0

    if "file_rename_count_60s" not in features.columns:
        features["file_rename_count_60s"] = 0

    if "smb_connection_count_60s" not in features.columns:
        features["smb_connection_count_60s"] = 0

    if "ransom_note_created" not in features.columns:
        features["ransom_note_created"] = 0

    if "suspicious_process_path" not in features.columns:
        features["suspicious_process_path"] = 0

    if "security_process_killed" not in features.columns:
        features["security_process_killed"] = 0

    if "avg_entropy_60s" not in features.columns:
        features["avg_entropy_60s"] = 0.0

    # Nếu chưa có log sửa file riêng, dùng tạm file_write_count
    features["modified_file_count_60s"] = features["file_write_count_60s"]

    return features


def add_entropy_change_feature(features):
    """
    Tạo đặc trưng avg_entropy_change_60s từ avg_entropy_60s.

    Vì log không lưu entropy trước khi file bị sửa,
    ta dùng ngưỡng 5.0 làm mức nền mô phỏng.
    Nếu entropy cao hơn 5.0 thì xem như có mức tăng entropy.
    """

    features = features.copy()

    if "avg_entropy_60s" not in features.columns:
        features["avg_entropy_60s"] = 0.0

    features["avg_entropy_change_60s"] = features["avg_entropy_60s"].apply(
        lambda x: max(0.0, float(x) - 5.0) if pd.notna(x) else 0.0
    )

    return features


def add_label_column(features):
    """
    Gán nhãn dữ liệu.

    Mặc định:
    - label = 0: bình thường

    Nếu xuất hiện dấu hiệu mạnh của hành vi LockerGoga-like,
    gán label = 1 để phục vụ mô phỏng huấn luyện/kiểm thử.
    """

    features = features.copy()
    features["label"] = 0

    ransomware_condition = (
        (
            features["file_write_count_60s"] > 100
        ) &
        (
            (features["file_rename_count_60s"] > 20) |
            (features["ransom_note_created"] == 1) |
            (features["security_process_killed"] == 1) |
            (features["avg_entropy_change_60s"] > 2.0)
        )
    )

    features.loc[ransomware_condition, "label"] = 1

    return features


def order_feature_columns(features):
    """
    Sắp xếp lại cột để dễ đọc và phù hợp mô hình.
    """

    selected_columns = [
        "time_window",
        "process_group",
        "file_write_count_60s",
        "file_rename_count_60s",
        "modified_file_count_60s",
        "avg_entropy_60s",
        "avg_entropy_change_60s",
        "smb_connection_count_60s",
        "ransom_note_created",
        "suspicious_process_path",
        "security_process_killed",
        "label"
    ]

    for col in selected_columns:
        if col not in features.columns:
            features[col] = 0

    return features[selected_columns]


def extract_features(input_file, output_file):
    """
    Pipeline trích xuất đặc trưng hoàn chỉnh.
    """

    df = load_preprocessed_logs(input_file)
    df = prepare_base_columns(df)

    # Đọc thêm log mô phỏng nếu có
    sim_df = load_simulation_events()

    if not sim_df.empty:
        df = pd.concat([df, sim_df], ignore_index=True)

    # Tính entropy thật từ các file trong target_file
    df = add_file_entropy_column(df)

    df = add_time_window(df, window="60s")
    df = normalize_process_group(df)

    file_write_feature = extract_file_write_count(df)
    smb_feature = extract_smb_connection_count(df)
    ransom_feature = extract_ransom_note_feature(df)
    suspicious_path_feature = extract_suspicious_path_feature(df)
    security_feature = extract_security_related_feature(df)
    rename_feature = extract_file_rename_count(df)
    entropy_feature = extract_entropy_feature(df)

    features = merge_features([
        file_write_feature,
        smb_feature,
        ransom_feature,
        suspicious_path_feature,
        security_feature,
        rename_feature,
        entropy_feature
    ])

    features = add_derived_features(features)
    features = add_entropy_change_feature(features)
    features = add_label_column(features)
    features = order_feature_columns(features)

    features.to_csv(output_file, index=False, encoding="utf-8-sig")

    print("Đã trích xuất đặc trưng.")
    print("File đầu vào:", input_file)
    print("File đầu ra:", output_file)
    print("Số dòng feature:", len(features))

    print("\nXem trước dữ liệu:")
    print(features.head(20))

    return features


if __name__ == "__main__":
    extract_features(
        input_file=r"C:\AI\LogExport\preprocessed_logs.csv",
        output_file=r"C:\AI\LogExport\features_dataset.csv"
    )