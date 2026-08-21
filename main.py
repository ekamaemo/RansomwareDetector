import json
from collections import deque


def method_risk_assessment(event, stats):
    # метод trust noone
    score = 0
    """
        stats – словарь с ключами:
            'score': баллы риска процесса
            'events': deque из (time, op, entropy_before, entropy_after, bytes) за последнюю секунду
            'signed': bool (подпись процесса)
    """
    curr_time = event["time"]
    op = event["op"]

    # проверка на то, сколько у процесса запросов за секунду, если их кол-во превышает порог, то это шифровальщик
    # окно с событиями происходящими в течение 1 секунды
    while stats["events"] and stats["events"][0][0] < curr_time - 1000:
        stats["events"].popleft()

    entropy_before = event.get("entropy_before")
    entropy_after = event.get("entropy_after")
    bytes_written = event.get("bytes", 0)
    stats["events"].append((curr_time, op, entropy_before, entropy_after, bytes_written))

    total = len(stats["events"])
    if total >= 40:
        score += 5 # подобрать лучший коэффициент

    # отбираем подозрительные операции
    suspicious = sum(1 for _, o, _, _, _ in stats["events"] if o in ("WRITE", "RENAME", "DELETE"))
    procent_susp_operations = suspicious / total

    # анализ энтропии после операций WRITE|RENAME + счет измененных байтов
    entropy_changes = []
    total_bytes = 0
    for _, o, eb, ea, ebytes in stats["events"]:
        if eb is not None and ea is not None and o in ("WRITE", "RENAME"):
            entropy_changes.append(ea - eb)
        if ebytes is not None:
            total_bytes += ebytes

    return score, verdict

# чтение входных данных

processes = []

p, n = map(int, input().split())

# Описание процесса содержит:
# • pid — целочисленный идентификатор процесса;
# • name — отображаемое имя процесса;
# • parent_pid — идентификатор родительского процесса или -1;
# • signed — наличие корректной цифровой подписи у исполняемого файла.
for i in range(p):
    processes.append(json.loads(input()))



# Каждое событие содержит обязательные поля:
# • time — время события в миллисекундах от начала сценария;
# • pid — идентификатор процесса;
# • op — операция CREATE, READ, WRITE, RENAME или DELETE;
# • signed — наличие корректной цифровой подписи у исполняемого файла;
# • path — путь к файлу внутри виртуальной файловой системы.
# Событие может содержать дополнительные поля: new_path для переименования, bytes для числа измененных
# байтов, size_before и size_after, а также entropy_before и entropy_after — условные оценки энтропии от 0 до 1.
events_by_pid = {}
for i in range(n):
    event = json.loads(input())
    pid =  event["pid"]

    if pid not in events_by_pid:
        events_by_pid[pid] = {"events": deque(), "signed": False, "score": 0}
    risk_score, verdict = method_risk_assessment(event, events_by_pid[pid])
    print(f"PID {pid} at time {event['time']}: {verdict} (score={risk_score})")

