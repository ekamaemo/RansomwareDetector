import time
import tracemalloc
import json
from main import analyze

# Список сценариев – каждый сценарий это два файла: processes.json и events.json
scenarios = [
    {"name": "locky", "data_path": "scenaries_for_test/locky.txt", "ans_path": "answers/ans_locky.txt"},

]

results = []

for scenario in scenarios:
    print(f"Запуск сценария: {scenario['name']}")
    tracemalloc.start()
    start_time = time.perf_counter()

    # Запускаем детектор (логи можно отключить, передав None)
    result_processes = analyze(scenario["data_path"])
    ans = [line.split() for line in open(scenario["ans_path"], "r").readlines()]
    end_time = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    elapsed = end_time - start_time
    count_blocked_ransomware = 0 # число обнаруженных вредоносных процессов
    count_blocked_safe = 0 # число ошибочно заблокированных процессов
    count_allow_ransomware = 0 # число ошибочно НЕзаблокированных процессов
    total_processes = len(result_processes)
    count_changed_files_by_ransomware = 0

    # Парсинг результатов
    for pid, right_verdict in ans:
        pid = int(pid)
        process = result_processes[pid]
        # допущение, что в одном сценарии либо один вредоносный процесс, либо вредоносные процессы относятся к одному вирусу(сценарий lockbit4)
        if process["state"] == "BLOCK" and right_verdict == "malicious":
            count_blocked_ransomware += 1
            count_changed_files_by_ransomware += len(process["changed_files"])
        elif process["state"] == "BLOCK" and right_verdict == "safe":
            count_blocked_safe += 1
        elif process["state"] == "ALLOW" and right_verdict == "malicious":
            count_allow_ransomware += 1
            count_changed_files_by_ransomware += len(process["changed_files"])

    results.append({
            "count_blocked_ransomware": count_blocked_ransomware,
            "count_blocked_safe": count_blocked_safe,
            "count_allow_ransomware": count_allow_ransomware,
            "count_changed_files": count_changed_files_by_ransomware,
            "total_processes": total_processes,
            "scenario": scenario['name'],
            "time_sec": elapsed,
            "peak_memory_mb": peak / 1024 / 1024
    })

# Сохраняем в CSV
import csv
with open("performance_results.csv", "w", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=["scenario", "count_blocked_ransomware", "count_blocked_safe", "count_allow_ransomware", "total_processes", "count_changed_files","time_sec", "peak_memory_mb"])
    writer.writeheader()
    writer.writerows(results)

print("\nИзмерения завершены. Результаты в performance_results.csv")