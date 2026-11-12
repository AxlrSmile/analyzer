import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).resolve().parents[1] / "plot_fix_experiments.py"
spec = importlib.util.spec_from_file_location("plot_fix_experiments", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PlotFixExperimentsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.csv = self.folder / "data.csv"
        self.svg = self.folder / "output.svg"

    def write_rows(self, data):
        with self.csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["number", "cwe", "verdict", "file"], delimiter=";")
            writer.writeheader()
            writer.writerows(data)

    def test_svg_counts_actual_entries(self):
        self.write_rows([
            {"number": 1, "cwe": "CWE-22", "verdict": "INCOMPLETE", "file": "Case002.java"},
            {"number": 2, "cwe": "CWE-89", "verdict": "PRELIMINARY_PASS", "file": "Case008.java"},
        ])
        self.assertEqual(2, module.make_chart(module.data_from_csv(self.csv), self.svg))
        root = ET.parse(self.svg).getroot()
        self.assertEqual("1080", root.attrib["width"])
        text = self.svg.read_text(encoding="utf-8")
        self.assertIn("CWE-22", text)
        self.assertIn("CWE-89", text)
        self.assertIn("попыток: 2", text)

    def test_empty_dataset_rejected(self):
        self.write_rows([])
        with self.assertRaisesRegex(ValueError, "Журнал пуст"):
            module.data_from_csv(self.csv)

    def test_unknown_verdict_rejected(self):
        self.write_rows([{"number": 1, "cwe": "CWE-22", "verdict": "SAFE", "file": "X.java"}])
        with self.assertRaisesRegex(ValueError, "Неизвестный статус"):
            module.data_from_csv(self.csv)

    def test_missing_headers_rejected(self):
        self.csv.write_text("foo;bar\n1;2\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Неверный формат"):
            module.data_from_csv(self.csv)

    def test_no_overwrite(self):
        self.write_rows([{"number": 1, "cwe": "CWE-22", "verdict": "INCOMPLETE", "file": "X.java"}])
        self.svg.write_text("keep", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            module.make_chart(module.data_from_csv(self.csv), self.svg)
        self.assertEqual("keep", self.svg.read_text(encoding="utf-8"))

    def test_svg_does_not_contain_raw_source_files(self):
        self.write_rows([{"number": 1, "cwe": "CWE-22", "verdict": "REJECTED", "file": "secret.java"}])
        module.make_chart(module.data_from_csv(self.csv), self.svg)
        self.assertNotIn("secret.java", self.svg.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
