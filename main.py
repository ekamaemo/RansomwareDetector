import json
# чтение входных данных

processes = []
events = []

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
events = {}
for i in range(n):
    event = json.loads(input())
    pid, verdict, decision_time, risk_score = event["pid"], '', 0, 0
    if pid not in events:
        events[pid] = [event]
    else:
        events[pid].append(event)

print(events)
