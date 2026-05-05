import pandas as pd
import random
from pathlib import Path


OUTPUT_FILE = r"LogExport\training_dataset.csv"


def generate_benign_samples(n=300):
    samples = []

    benign_processes = [
        r"c:\windows\system32\notepad.exe",
        r"c:\program files\google\chrome\application\chrome.exe",
        r"c:\program files\microsoft office\root\office16\winword.exe",
        r"c:\program files\microsoft office\root\office16\excel.exe",
        r"c:\windows\explorer.exe",
        r"c:\program files\7-zip\7z.exe",
        r"c:\program files\backupsoft\backup.exe",
        r"c:\users\tienh\appdata\local\microsoft\onedrive\onedrive.exe"
    ]

    for i in range(n):
        process = random.choice(benign_processes)

        if "backup" in process or "7z" in process:
            file_write = random.randint(50, 180)
            file_rename = random.randint(0, 8)
            modified_file = file_write + random.randint(0, 20)
            entropy = round(random.uniform(4.5, 6.3), 2)
            entropy_change = round(random.uniform(0.0, 1.2), 2)
        else:
            file_write = random.randint(0, 80)
            file_rename = random.randint(0, 5)
            modified_file = file_write + random.randint(0, 10)
            entropy = round(random.uniform(3.5, 5.8), 2)
            entropy_change = round(random.uniform(0.0, 0.8), 2)

        samples.append({
            "time_window": f"benign_{i}",
            "process_group": process,
            "file_write_count_60s": file_write,
            "file_rename_count_60s": file_rename,
            "modified_file_count_60s": modified_file,
            "avg_entropy_60s": entropy,
            "avg_entropy_change_60s": entropy_change,
            "smb_connection_count_60s": random.randint(0, 4),
            "ransom_note_created": 0,
            "suspicious_process_path": 1 if "appdata" in process else 0,
            "security_process_killed": 0,
            "label": 0
        })

    return samples


def generate_lockergoga_samples(n=300):
    samples = []

    ransomware_processes = [
        r"temp\security_update.exe",
        r"downloads\update_service.exe",
        r"public\locker_sim.exe",
        r"temp\temp_runner.exe",
        r"programdata\service_update.exe"
    ]

    for i in range(n):
        process = random.choice(ransomware_processes)

        file_write = random.randint(250, 1200)
        file_rename = random.randint(80, 800)
        modified_file = file_write + random.randint(50, 200)

        samples.append({
            "time_window": f"lockergoga_{i}",
            "process_group": process,
            "file_write_count_60s": file_write,
            "file_rename_count_60s": file_rename,
            "modified_file_count_60s": modified_file,
            "avg_entropy_60s": round(random.uniform(6.8, 7.9), 2),
            "avg_entropy_change_60s": round(random.uniform(1.8, 3.5), 2),
            "smb_connection_count_60s": random.randint(5, 30),
            "ransom_note_created": random.choice([1, 1, 1, 0]),
            "suspicious_process_path": 1,
            "security_process_killed": random.choice([0, 1, 1]),
            "label": 1
        })

    return samples


def generate_edge_cases(n=100):
    samples = []

    for i in range(n):
        case_type = random.choice(["backup", "zip", "appdata_normal"])

        if case_type == "backup":
            process = r"c:\program files\backupsoft\backup.exe"
            samples.append({
                "time_window": f"edge_backup_{i}",
                "process_group": process,
                "file_write_count_60s": random.randint(120, 300),
                "file_rename_count_60s": random.randint(0, 8),
                "modified_file_count_60s": random.randint(120, 320),
                "avg_entropy_60s": round(random.uniform(4.5, 6.2), 2),
                "avg_entropy_change_60s": round(random.uniform(0.2, 1.2), 2),
                "smb_connection_count_60s": random.randint(0, 5),
                "ransom_note_created": 0,
                "suspicious_process_path": 0,
                "security_process_killed": 0,
                "label": 0
            })

        elif case_type == "zip":
            process = r"program files\7-zip\7z.exe"
            samples.append({
                "time_window": f"edge_zip_{i}",
                "process_group": process,
                "file_write_count_60s": random.randint(40, 160),
                "file_rename_count_60s": random.randint(0, 5),
                "modified_file_count_60s": random.randint(40, 170),
                "avg_entropy_60s": round(random.uniform(6.0, 7.5), 2),
                "avg_entropy_change_60s": round(random.uniform(0.8, 2.0), 2),
                "smb_connection_count_60s": random.randint(0, 3),
                "ransom_note_created": 0,
                "suspicious_process_path": 0,
                "security_process_killed": 0,
                "label": 0
            })

        else:
            process = r"temp\normal_installer.exe"
            samples.append({
                "time_window": f"edge_appdata_{i}",
                "process_group": process,
                "file_write_count_60s": random.randint(5, 80),
                "file_rename_count_60s": random.randint(0, 4),
                "modified_file_count_60s": random.randint(5, 90),
                "avg_entropy_60s": round(random.uniform(3.8, 5.8), 2),
                "avg_entropy_change_60s": round(random.uniform(0.0, 0.8), 2),
                "smb_connection_count_60s": random.randint(0, 2),
                "ransom_note_created": 0,
                "suspicious_process_path": 1,
                "security_process_killed": 0,
                "label": 0
            })

    return samples


def main():
    random.seed(42)

    data = []
    data.extend(generate_benign_samples(300))
    data.extend(generate_lockergoga_samples(300))
    data.extend(generate_edge_cases(100))

    df = pd.DataFrame(data)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    output_path = Path(OUTPUT_FILE)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(output_path, index=False, encoding="utf-8-sig")

    print("Da tao training dataset:", output_path)
    print("Tong so dong:", len(df))
    print("\nPhan bo label:")
    print(df["label"].value_counts())

    print("\nXem truoc:")
    print(df.head(10))


if __name__ == "__main__":
    main()
