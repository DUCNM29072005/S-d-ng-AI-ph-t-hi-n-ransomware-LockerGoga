import pandas as pd
import numpy as np

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import sys

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


def load_feature_dataset(input_file):
    """
    Đọc file features_dataset.csv đã tạo ở bước trích xuất đặc trưng.
    """

    df = pd.read_csv(input_file)

    required_columns = FEATURE_COLUMNS + ["label"]

    for col in required_columns:
        if col not in df.columns:
            df[col] = 0

    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)

    return df


def split_xy(df):
    """
    Tách dữ liệu thành X và y.
    """

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    return X, y


def train_random_forest(X, y):
    """
    Huấn luyện Random Forest.
    """

    if y.nunique() < 2:
        print("[WARNING] Dữ liệu chỉ có một lớp label.")
        print("Random Forest cần cả label 0 và label 1 để học phân loại.")
        print("Bạn cần tạo thêm dữ liệu mô phỏng LockerGoga-like hoặc gán nhãn lại.")
        return None, None, None, None

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.3,
        random_state=42,
        stratify=y
    )

    rf_model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    rf_model.fit(X_train, y_train)

    y_pred = rf_model.predict(X_test)

    print("\n=== KẾT QUẢ RANDOM FOREST ===")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    return rf_model, X_train, X_test, y_test


def train_isolation_forest(X, y):
    """
    Huấn luyện Isolation Forest chủ yếu trên dữ liệu bình thường label = 0.
    """

    X_benign = X[y == 0]

    if len(X_benign) == 0:
        print("[WARNING] Không có dữ liệu benign để train Isolation Forest.")
        print("Sẽ train Isolation Forest trên toàn bộ dữ liệu.")
        X_benign = X

    iso_model = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42
    )

    iso_model.fit(X_benign)

    return iso_model


def normalize_if_scores(raw_scores):
    """
    Chuyển điểm Isolation Forest thành IF_score từ 0 đến 1.
    raw_scores càng thấp thì càng bất thường.
    """

    anomaly_scores = -raw_scores

    min_score = anomaly_scores.min()
    max_score = anomaly_scores.max()

    if max_score - min_score == 0:
        return np.zeros_like(anomaly_scores)

    return (anomaly_scores - min_score) / (max_score - min_score)


def calculate_rule_score(row):
    """
    Tính Rule Score dựa trên các dấu hiệu mạnh.
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
    Phân loại mức cảnh báo dựa trên Risk Score.
    """

    if risk_score >= 0.81:
        return "Ransomware / LockerGoga-like"
    elif risk_score >= 0.61:
        return "Nguy cơ cao"
    elif risk_score >= 0.31:
        return "Nghi ngờ"
    else:
        return "Bình thường"


def detect_with_risk_score(df, rf_model, iso_model):
    """
    Tính RF_score, IF_score, Rule_score, Risk_score cho từng mẫu.
    """

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

    return results


def show_feature_importance(rf_model):
    """
    Hiển thị mức độ quan trọng của các đặc trưng.
    """

    if rf_model is None:
        return

    importance_df = pd.DataFrame({
        "feature": FEATURE_COLUMNS,
        "importance": rf_model.feature_importances_
    }).sort_values(by="importance", ascending=False)

    print("\n=== FEATURE IMPORTANCE ===")
    print(importance_df)

    return importance_df


def save_models(rf_model, iso_model, output_folder):
    """
    Lưu mô hình đã huấn luyện.
    """

    output_folder = Path(output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)

    if rf_model is not None:
        joblib.dump(rf_model, output_folder / "random_forest_model.pkl")

    joblib.dump(iso_model, output_folder / "isolation_forest_model.pkl")

    print("\nĐã lưu mô hình vào:", output_folder)


def train_pipeline(input_file, output_folder):
    """
    Pipeline huấn luyện hoàn chỉnh.
    """

    df = load_feature_dataset(input_file)

    print("Đã đọc dataset:", input_file)
    print("Số dòng:", len(df))
    print("\nPhân bố label:")
    print(df["label"].value_counts())

    X, y = split_xy(df)

    rf_model, X_train, X_test, y_test = train_random_forest(X, y)
    iso_model = train_isolation_forest(X, y)

    importance_df = show_feature_importance(rf_model)

    results = detect_with_risk_score(df, rf_model, iso_model)

    output_folder = Path(output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)

    results_file = output_folder / "detection_results.csv"
    results.to_csv(results_file, index=False, encoding="utf-8-sig")

    if importance_df is not None:
        importance_file = output_folder / "feature_importance.csv"
        importance_df.to_csv(importance_file, index=False, encoding="utf-8-sig")

    save_models(rf_model, iso_model, output_folder)

    print("\n=== KẾT QUẢ NHẬN DIỆN ===")

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

    print(results[available_columns].head(30))

    print("\nĐã lưu kết quả tại:", results_file)


if __name__ == "__main__":
    train_pipeline(
        input_file=r"C:\AI\LogExport\training_dataset.csv",
        output_folder=r"C:\AI\LogExport\ModelOutput"
    )