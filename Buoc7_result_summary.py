import pandas as pd
from pathlib import Path
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

def summarize_results(input_file, output_file):
    df = pd.read_csv(input_file)

    selected_columns = [
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

    available_columns = [col for col in selected_columns if col in df.columns]

    summary = df[available_columns].copy()

    # Sắp xếp theo Risk_score từ cao xuống thấp
    if "Risk_score" in summary.columns:
        summary = summary.sort_values(by="Risk_score", ascending=False)

    summary.to_csv(output_file, index=False, encoding="utf-8-sig")

    print("Đã tạo bảng tổng hợp kết quả.")
    print("File đầu vào:", input_file)
    print("File đầu ra:", output_file)

    print("\nTop kết quả có Risk_score cao nhất:")
    print(summary.head(20))


if __name__ == "__main__":
    summarize_results(
        input_file=r"LogExport\ModelOutput\new_detection_results.csv",
        output_file=r"LogExport\ModelOutput\summary_results.csv"
    )
