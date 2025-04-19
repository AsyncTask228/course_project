# analyzers/report.py

from datetime import datetime

# Импорт всех анализаторов как функций
from analyzers import (
    auth_analyzer,
    ssh_analyzer,
    session_analyzer,
    network_analyzer,
    process_analyzer,
    file_analyzer,
    device_analyzer
)

# Список анализаторов: (имя, функция)
ANALYZERS = [
    ("auth", auth_analyzer),
    ("ssh", ssh_analyzer),
    ("session", session_analyzer),
    ("network", network_analyzer),
    ("process", process_analyzer),
    ("file", file_analyzer),
    ("device", device_analyzer)
]


def run_all():
    all_alerts = []

    print("🚀 Запуск всех анализаторов...\n")
    for name, analyzer_func in ANALYZERS:
        try:
            print(f"🔍 Анализ: {name}_analyzer...")
            alerts = analyzer_func()
            all_alerts.extend(alerts)
            print(f"✅ {name}_analyzer: найдено {len(alerts)} событий.\n")
        except Exception as e:
            print(f"❌ Ошибка при выполнении {name}_analyzer: {e}")

    return sorted(all_alerts, key=lambda x: x['timestamp'])


def print_report(alerts):
    print("\n📊 [Итоговый отчёт по аномалиям]\n")
    for a in alerts:
        print(f"[{a['severity'].upper()}] ({a['type']}) {a['username']} @ {a['timestamp']} → {a['message']} [score: {a.get('risk_score', '?')}]")

    print(f"\n📦 Всего событий: {len(alerts)}")


def save_to_file(alerts, path="anomaly_report.txt"):
    with open(path, "w") as f:
        f.write("Анализ аномалий (" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ")\n\n")
        for a in alerts:
            f.write(f"[{a['severity'].upper()}] ({a['type']}) {a['username']} @ {a['timestamp']} → {a['message']} [score: {a.get('risk_score', '?')}]\n")
    print(f"\n📁 Отчёт сохранён в: {path}")


if __name__ == "__main__":
    alerts = run_all()
    print_report(alerts)
    save_to_file(alerts)
