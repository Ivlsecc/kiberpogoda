import argparse
import sys
from pathlib import Path

from collect import collect_all
from score import score_companies, PROFILE_WEIGHTS

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parents[1]

GROUP_NAME = {
    "A": "ценность (A)", "E": "поверхность атаки (E)",
    "O": "готовая возможность (O)", "I": "намерение/тренд (I)",
}
RECO = {
    "A": "Ценность не снижается — компенсируется зрелостью защиты: сегментация, защита "
         "критичных данных (ПДн/платежи), план реагирования и резервные копии оффлайн.",
    "E": "Сократить внешнюю поверхность: инвентаризация поддоменов из CT, вывод тестовых/"
         "служебных сервисов из интернета, обновление периметрового ПО, усиление ИБ-команды.",
    "O": "Закрыть «готовую возможность»: принудительная смена паролей и MFA (утёкшие учётки), "
         "мониторинг теневых площадок на продажу доступов, срочный патч уязвимого массового ПО.",
    "I": "Повышенный текущий интерес: усилить мониторинг и threat hunting, проверить IOC групп, "
         "активных по отрасли, приоритизировать закрытие свежих уязвимостей в своём стеке.",
}


def confidence_phrase(conf):
    if conf >= 0.85:
        return f"высокая уверенность ({conf:.0%}) — данные полны, это вывод"
    if conf >= 0.6:
        return f"средняя уверенность ({conf:.0%}) — часть данных отсутствует"
    return (f"низкая уверенность ({conf:.0%}) — данных не хватает; это ГИПОТЕЗА, "
            f"требуется доразведка, а не готовый вывод")


def build_report(data, profile, top):
    results = score_companies(data, profile=profile)
    w = PROFILE_WEIGHTS[profile]
    lines = [f"# Пояснительные карточки целей — профиль «{profile}»\n",
             f"Веса модели: A={w['A']}, E={w['E']}, O={w['O']}, I={w['I']}. "
             f"Балл = приоритет по интересу/привлекательности, не прогноз атаки.\n"]
    for i, r in enumerate(results[:top], 1):
        contrib = r["contrib"]
        drivers = r["top_drivers"]
        drv_txt = " и ".join(GROUP_NAME[d] for d in drivers)
        lines.append(f"\n## {i}. {r['name']} ({r['domain']}) — Score {r['score']} / 100\n")
        lines.append(f"- **Уверенность:** {confidence_phrase(r['confidence'])}.")
        lines.append(f"- **Вклад факторов (из 100):** "
                     f"A={contrib['A']}, E={contrib['E']}, O={contrib['O']}, I={contrib['I']}.")
        lines.append(f"- **Главные драйверы:** {drv_txt}.")
        g = r["groups"]
        strong = [GROUP_NAME[k] for k in ("A", "E", "O", "I") if g[k] >= 0.6]
        weak = [GROUP_NAME[k] for k in ("A", "E", "O", "I") if g[k] < 0.3]
        expl = f"  Компания поднимается в рейтинге за счёт: {', '.join(strong) or '—'}."
        if weak:
            expl += f" Снижают приоритет: {', '.join(weak)}."
        lines.append(expl)
        lines.append(f"- **Что делать защитнику (приоритет):** {RECO[drivers[0]]}")
    lines.append("\n> Итог предназначен для приоритизации защиты, а не для нападения. "
                 "Интерес к компании ≠ атака: это вход для усиления мониторинга и периметра.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--profile", default="ransomware", choices=list(PROFILE_WEIGHTS))
    ap.add_argument("--top", type=int, default=5)
    args = ap.parse_args()

    data = collect_all(BASE / "data" / "companies.json", live=not args.offline,
                       monitor_path=BASE.parent / "task3_monitoring" / "output" / "posts.jsonl")
    text = build_report(data, args.profile, args.top)
    (BASE / "output").mkdir(exist_ok=True)
    out = BASE / "output" / f"company_reports_{args.profile}.md"
    out.write_text(text, encoding="utf-8")
    print(f"[+] Карточки сохранены: {out}")
    print(text[:1200])


if __name__ == "__main__":
    main()
