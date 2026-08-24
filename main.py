import json
import sys
from collections import deque
from datetime import datetime


def analyze(path_to_data=None):
    if path_to_data is not None:
        in_stream = open(path_to_data, 'r', encoding='utf-8')
    else:
        in_stream = sys.stdin
    processes_by_pid = {}

    with in_stream as f:
        line = f.readline()
        if not line:
            return
        p, n = map(int, line.split())
        # Описание процесса содержит:
        # • pid — целочисленный идентификатор процесса;
        # • name — отображаемое имя процесса;
        # • parent_pid — идентификатор родительского процесса или -1;
        # • signed — наличие корректной цифровой подписи у исполняемого файла.
        for i in range(p):
            line = f.readline()
            if not line:
                break
            process = json.loads(line)
            pid, name, parent_pid, signed = process["pid"], process["name"], process["parent_pid"], process["signed"]
            processes_by_pid[pid] = {
                "state": "ALLOW",
                "events": deque(),
                "signed": signed,
                "score": 0,
                "total_events": 0,
                "first_observe": None,
                "first_block": None,
                "parent_pid": parent_pid,
                "changed_files": set()
            }

        # открытие файла для записи логов
        log_file = open("risk_details.txt", "a", encoding="utf-8")
        log_file.write(f"\n=== NEW RUN at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")

        # Каждое событие содержит обязательные поля:
        # • time — время события в миллисекундах от начала сценария;
        # • pid — идентификатор процесса;
        # • op — операция CREATE, READ, WRITE, RENAME или DELETE;
        # • signed — наличие корректной цифровой подписи у исполняемого файла;
        # • path — путь к файлу внутри виртуальной файловой системы.
        # Событие может содержать дополнительные поля: new_path для переименования, bytes для числа измененных
        # байтов, size_before и size_after, а также entropy_before и entropy_after — условные оценки энтропии от 0 до 1.

        for i in range(n):
            line = f.readline()
            if not line:
                break
            event = json.loads(line)
            pid = event["pid"]
            if pid not in processes_by_pid:
                continue
            details = method_risk_assessment(event, processes_by_pid[pid])
            # Записываем информацию о событии в лог
            if details is None:
                log_file.write(
                    f"Event IGNORED (process already BLOCKED): time={event['time']}, pid={pid}, op={event['op']}\n\n")
            else:
                log_file.write(
                    f"Event: time={event['time']}, pid={pid}, op={event['op']}, path={event.get('path', '')}, new_path={event.get('new_path', '')}\n")
                if details:
                    for rule, score in details.items():
                        log_file.write(f"  - {rule}: +{score}\n")
                else:
                    log_file.write("  - no penalties or bonuses\n")
                log_file.write("\n")

                # Если процесс только что стал BLOCK, блокируем всех его потомков
            if details is not None and processes_by_pid[pid]["state"] == "BLOCK" and \
                    processes_by_pid[pid]["first_block"] == event["time"]:
                block_descendants(pid, event["time"], processes_by_pid, log_file)

        log_file.close()
        out_lines = []

        for pid in processes_by_pid:
            stats = processes_by_pid[pid]
            if stats["state"] == "BLOCK":
                verdict = "BLOCK"
                decision_time = stats["first_block"] if stats["first_block"] is not None else -1
            elif stats["state"] == "OBSERVE":
                verdict = "OBSERVE"
                decision_time = stats["first_observe"] if stats["first_observe"] is not None else -1
            else:
                verdict = "ALLOW"
                decision_time = -1

            risk_score = stats["score"] / stats["total_events"] if stats["total_events"] > 0 else 0

            out_lines.append(f"{pid} {verdict} {decision_time} {risk_score}")
        sys.stdout.write("\n".join(out_lines))
        return processes_by_pid



def block_descendants(pid, current_time, processes_by_pid, log_file):
    """Блокирует все процессы, являющиеся потомками pid (включая вложенных)."""
    stack = [pid]
    visited = set()
    visited.add(pid)

    while stack:
        current_pid = stack.pop()

        for child_pid, child_stats in processes_by_pid.items():
            if child_stats.get("parent_pid") == current_pid and child_pid not in visited:
                if child_stats["state"] != "BLOCK":
                    child_stats["state"] = "BLOCK"
                    if child_stats["first_block"] is None:
                        child_stats["first_block"] = current_time
                    log_file.write(
                        f"  >> Descendant process {child_pid} blocked "
                        f"(parent {current_pid} blocked at time {current_time})\n"
                    )
                visited.add(child_pid)
                stack.append(child_pid)


def method_risk_assessment(event, stats):
    # метод накопление баллов риска

    """
        stats – словарь с ключами:
            'state': текущий статус
            'score': баллы риска процесса
            'events': deque из (time, op, entropy_before, entropy_after, bytes) за последнюю секунду
            'signed': bool (подпись процесса)
            'first_observe': int or None (время первого перехода в OBSERVE)
            'first_block': int or None (время первого перехода в BLOCK)
            'parent_pid': айди родителя-процесса
    """

    if stats["state"] == "BLOCK":
        return

    # Настройки порогов (на тестировании надо менять, чтобы подобрать лучшие баллы - высшая точность нахождения шифровальщика)
    SUSP_RATIO_THRESHOLD = 0.6  # доля WRITE/RENAME/DELETE – штраф
    ENTROPY_MEAN_THRESHOLD = 0.4  # средний рост энтропии при WRITE/RENAME – штраф
    ENTROPY_MEAN_MODERATE = 0.2  # умеренный средний рост – меньший штраф
    ENTROPY_MAX_THRESHOLD = 0.6  # максимальный скачок энтропии – доп. штраф
    BYTES_THRESHOLD = 10 * 1024 * 1024  # 10 МБ за секунду – штраф
    HIGH_EVENT_RISK = 75
    MODERATE_EVENT_RISK = 45


    delta = 0 # счетчик баллов текущего события
    details = {} # для логгирования

    # для проверки на место работы процесса
    USER_FOLDERS = {'documents', 'desktop', 'pictures', 'music', 'videos', 'downloads'}
    SYSTEM_FOLDERS = {'windows', 'program files', 'system32'}

    # Белый список — безопасные расширения
    SAFE_EXTENSIONS = {
        '.txt', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.rtf',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
        '.mp3', '.mp4', '.avi', '.wav',
        '.zip', '.rar', '.7z', '.tar', '.gz'
    }

    # Чёрный список — известные расширения шифровальщиков
    RANSOMWARE_EXTENSIONS = {
        '.locky', '.crypt', '.cryptolocker', '.wannacry',
        '.cerber', '.encrypted', '.zepto', '.locked',
        '.qilin', '.play', '.lockbit', '.clop', '.cl0p', '.medusa'  # из актуальных списков[reference:18]
    }
    curr_time = event["time"]
    op = event["op"]
    signed = event.get("signed", False)
    path = event.get("path", "")
    new_path = event.get("new_path", "")
    entropy_before = event.get("entropy_before")
    entropy_after = event.get("entropy_after")
    bytes_written = event.get("bytes", 0)
    size_before = event.get("size_before")
    size_after = event.get("size_after")

    # для отслеживания измененных файлов
    if op == "WRITE" and path:
        stats["changed_files"].add(path)

    # проверка подписи цифровой
    if not signed and not stats["signed"]:
        details["unsigned_process"] = 20
        delta += 20
    elif not signed:
        details["unsigned_event"] = 5
        delta += 5
    elif signed and not stats["signed"]:
        delta += 10
        details["signed_mismatch"] = 10

    # --- проверка расширения
    ext = ""
    if op == "RENAME" and new_path:
        ext = "." + new_path.split(".")[-1]
    elif path:
        ext = "." + path.split(".")[-1]
    if ext in RANSOMWARE_EXTENSIONS:
        delta += 30
        details["ransomware_extension"] = 30
    elif ext not in SAFE_EXTENSIONS:
        delta += 10
        details["safe_extension"] = 10

    # --- проверка на взаимодействие с теневыми копиями
    if op in ("CREATE", "RENAME"):
        target = new_path if op == "RENAME" else path
        if target and ("vssadmin" in target.lower() or "wmic" in target.lower()):
            delta += 40
            details["shadow_copy_interaction"] = 40

    # --- проверка, что событие работает с пользовательским файлом
    is_user = any(folder in path.lower() for folder in USER_FOLDERS)
    is_system = any(folder in path.lower() for folder in SYSTEM_FOLDERS)
    if is_user and not is_system:
        delta += 5
        details["user_folder"] = 5

    # --- проверка на изменение файла целиком
    if op == "WRITE" and size_before is not None and size_before > 0 and bytes_written > 0:
        if bytes_written >= 0.9 * size_before:
            delta += 20
            details["full_file_overwrite"] = 20

    # --- проверка на слишком интенсивную работу с файлами
    if stats["total_events"] > 10000:
        delta += 10
        details["high_total_events"] = 10

    # --- проверка на то, сколько у процесса запросов за секунду, если их кол-во превышает порог, то это шифровальщик
    # окно с событиями происходящими в течение 1 секунды
    while stats["events"] and stats["events"][0][0] < curr_time - 1000:
        stats["events"].popleft()

    stats["events"].append((curr_time, op, entropy_before, entropy_after, bytes_written))


    total = len(stats["events"])
    # --- проверка на соотношение подозрительных и всех операций
    if total > 0:
        suspicious = sum(1 for _, o, _, _, _ in stats["events"] if o in ("WRITE", "RENAME", "DELETE"))
        ratio_susp_operations = suspicious / total
        if ratio_susp_operations >= SUSP_RATIO_THRESHOLD and total > 2:
            delta += 20
            details["suspicious_operation_ratio"] = 20

    # --- (проверка) анализ энтропии после операций WRITE|RENAME
    entropy_changes = []
    for _, o, eb, ea, _ in stats["events"]:
        if eb is not None and ea is not None and o in ("WRITE", "RENAME"):
            entropy_changes.append(ea - eb)
    if entropy_changes:
        mean_change = sum(entropy_changes) / len(entropy_changes)
        max_change = max(entropy_changes)
        if mean_change >= ENTROPY_MEAN_THRESHOLD:
            delta += 40
            details["entropy_mean_high"] = 40
        elif mean_change >= ENTROPY_MEAN_MODERATE:
            delta += 10
            details["entropy_mean_moderate"] = 10
        if max_change >= ENTROPY_MAX_THRESHOLD:
            delta += 10
            details["entropy_max_rise"] = 10

    # --- (проверка) подсчет объема записанных данных
    total_bytes = sum(ebytes for _, _, _, _, ebytes in stats["events"] if ebytes)
    if total_bytes >= BYTES_THRESHOLD:
        delta += 10
        details["high_bytes_volume"] = 10


    stats["score"] += max(0, min(100, delta))
    stats["total_events"] += 1
    avg_risk = stats["score"] / stats["total_events"]
    if avg_risk <= 30:
        new_verdict = "ALLOW"
    elif avg_risk <= 60:
        new_verdict = "OBSERVE"
    else:
        new_verdict = "BLOCK"

    if stats["state"] == "ALLOW":
        if new_verdict != "ALLOW":
            stats["state"] = new_verdict
            if new_verdict == "OBSERVE" and stats["first_observe"] is None:
                stats["first_observe"] = curr_time
            elif new_verdict == "BLOCK" and stats["first_block"] is None:
                stats["first_block"] = curr_time
    elif stats["state"] == "OBSERVE":
        if new_verdict == "BLOCK":
            stats["state"] = "BLOCK"
            if stats["first_block"] is None:
                stats["first_block"] = curr_time

    return details



if __name__ == "__main__":
    # Если передан аргумент командной строки – читаем из файла
    if len(sys.argv) > 1:
        analyze(sys.argv[1])
    else:
        # Иначе используем стандартный ввод (как раньше)
        analyze()   # будет читать из sys.stdin