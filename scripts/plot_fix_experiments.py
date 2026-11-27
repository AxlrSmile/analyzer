#!/usr/bin/env python3
"""Render an offline SVG chart from v8.9 FixExperimentService CSV.

No network, dependencies, code execution, or fabricated results. The chart visualizes
recorded attempts, not security certifications. All labels are XML-escaped by ElementTree.
"""
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET

VERDICTS = ("PRELIMINARY_PASS", "REVIEW_REQUIRED", "INCOMPLETE", "REJECTED")
COLORS = {
    "PRELIMINARY_PASS": "#167d62",
    "REVIEW_REQUIRED": "#c48b17",
    "INCOMPLETE": "#64748b",
    "REJECTED": "#b94b4b",
}
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)


def data_from_csv(source: Path):
    with source.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter=";")
        if not reader.fieldnames or not {"cwe", "verdict", "file"}.issubset(reader.fieldnames):
            raise ValueError("Неверный формат CSV: ожидаются столбцы cwe, verdict, file")
        data = list(reader)
    if not data:
        raise ValueError("Журнал пуст: нечего визуализировать")
    if len(data) > 10_000:
        raise ValueError("Журнал слишком большой для одного графика")
    for row in data:
        if row["verdict"] not in VERDICTS:
            raise ValueError("Неизвестный статус эксперимента: " + row["verdict"][:80])
        if not row["cwe"].startswith("CWE-") or len(row["cwe"]) > 20:
            raise ValueError("Некорректная метка CWE")
    return data


def make_chart(rows, output: Path):
    groups = defaultdict(Counter)
    for row in rows:
        groups[row["cwe"]][row["verdict"]] += 1
    labels = sorted(groups)
    width = 1080
    height = 210 + 54 * len(labels)
    svg = ET.Element(f"{{{NS}}}svg", {
        "width": str(width), "height": str(height), "viewBox": f"0 0 {width} {height}",
        "role": "img", "aria-label": "Итоги проверок исправлений по CWE",
    })

    def add(tag, attrs=None, text=None):
        el = ET.SubElement(svg, f"{{{NS}}}{tag}", attrs or {})
        if text is not None:
            el.text = str(text)
        return el

    add("rect", {"width": str(width), "height": str(height), "fill": "#ffffff"})
    add("text", {"x": "30", "y": "39", "font-size": "23", "font-weight": "700", "fill": "#172b45"},
        "Fix Recommendation Agent — результаты экспериментов 8.9")
    add("text", {"x": "30", "y": "67", "font-size": "15", "fill": "#475569"},
        f"Записано попыток: {len(rows)}. Статусы не являются сертификатами безопасности.")
    x = 30
    for v in VERDICTS:
        add("rect", {"x": str(x), "y": "87", "width": "15", "height": "15", "rx": "3", "fill": COLORS[v]})
        add("text", {"x": str(x + 20), "y": "100", "font-size": "12", "fill": "#334155"}, v)
        x += 245
    max_total = max(sum(groups[k].values()) for k in labels)
    px_per = 760 / max_total
    for i, cwe in enumerate(labels):
        y = 145 + 54 * i
        add("text", {"x": "30", "y": str(y + 20), "font-size": "16", "fill": "#172b45"}, cwe)
        start = 165
        for verdict in VERDICTS:
            n = groups[cwe][verdict]
            if n:
                w = n * px_per
                add("rect", {"x": str(start), "y": str(y), "width": str(w), "height": "29",
                             "rx": "2", "fill": COLORS[verdict]})
                if w > 30:
                    add("text", {"x": str(start + w / 2), "y": str(y + 20),
                                 "text-anchor": "middle", "font-size": "14", "fill": "#ffffff"}, n)
                start += w
        add("text", {"x": "955", "y": str(y + 20), "font-size": "14", "fill": "#334155"},
            f"n={sum(groups[cwe].values())}")
    add("text", {"x": "30", "y": str(height - 23), "font-size": "13", "fill": "#64748b"},
        "SKIPPED / NOT_CHECKED в функциональных тестах учитываются статусом INCOMPLETE. Ревью обязательно.")
    if output.exists():
        raise FileExistsError("График уже существует. Используйте другое имя файла.")
    if not output.parent.is_dir():
        raise FileNotFoundError("Каталог для графика не существует")
    payload = ET.tostring(svg, encoding="utf-8", xml_declaration=True)
    with output.open("xb") as f:
        f.write(payload)
    return len(groups)


def main():
    parser = argparse.ArgumentParser(description="График по реальному CSV журнала Fix Agent 8.9")
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--svg", type=Path, required=True)
    args = parser.parse_args()
    rows = data_from_csv(args.csv)
    count = make_chart(rows, args.svg)
    print(f"Готово: {args.svg} — попыток {len(rows)}, категорий CWE {count}")


if __name__ == "__main__":
    main()
