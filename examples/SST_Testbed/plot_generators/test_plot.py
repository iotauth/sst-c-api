"""Run with: python3 -m unittest discover -s examples/SST_Testbed/plot_generators."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import plot


class PlotTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_csv(self, name, rows):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("malicious_number,attempt_rate_per_s,avg_us\n" + rows)
        return path

    def test_prepared_rows_and_latency_units(self):
        path = self.write_csv("prepared.csv", "2,10,1000\n2,20,2000\n2,30,3000\n")
        args = plot.make_parser().parse_args(["--latency", str(path)])
        series, count, raw = plot.load_points(args, plot.make_parser(), "latency")
        self.assertEqual((count, raw), (1, False))
        for index, label in enumerate(plot.SERIES_ORDER):
            self.assertEqual(series[label], [{"label": label, "malicious_number": 2.0,
                                             "y": float(index + 1)}])

    def test_raw_metrics_average_across_files(self):
        first = self.write_csv("one.csv", "3,10,1000\n3,30,3000\n")
        second = self.write_csv("two.csv", "3,40,5000\n")
        args = plot.make_parser().parse_args([
            "--throughput", "--config1", str(first), "--config1", str(second)])
        series, count, raw = plot.load_points(args, plot.make_parser(), "throughput")
        self.assertEqual((count, raw), (2, True))
        # Preserve the existing mean-of-file-means aggregation.
        self.assertEqual(series[plot.CONFIG_1][0]["y"], 30.0)
        self.assertEqual(series[plot.CONFIG_2], [])

    def test_explicit_paths_globs_recursion_and_deduplication(self):
        first = self.write_csv("one.csv", "1,2,3\n")
        second = self.write_csv("nested/two.csv", "1,2,3\n")
        files = plot.expand_inputs([str(first), str(self.root / "*.csv"), str(self.root)], True)
        self.assertEqual(set(map(Path, files)), {first, second})
        self.assertEqual(len(files), 2)
        # Caller-selected absolute paths outside the working directory remain supported.
        self.assertEqual(plot.expand_inputs([str(second)], False), [str(second)])

    def test_axes_inset_and_output_collision(self):
        path = self.write_csv("prepared.csv", "2,10,1000\n2,20,2000\n2,30,3000\n")
        args = plot.make_parser().parse_args([
            "--latency", str(path), "--inset", "--xlim", "0", "4"])
        series, _, _ = plot.load_points(args, plot.make_parser(), "latency")
        figure, axis = plt.subplots()
        self.addCleanup(plt.close, figure)
        x_values, y_values = plot.plot_series(axis, series)
        plot.configure_axes(axis, args, "latency", x_values)
        plot.draw_inset(axis, args, series, y_values)
        plot.order_legend(axis)
        self.assertEqual(axis.get_ylabel(), "Latency (ms)")
        self.assertEqual(tuple(axis.get_xlim()), (0.0, 4.0))
        self.assertEqual([text.get_text() for text in axis.get_legend().get_texts()], plot.SERIES_ORDER)
        self.assertAlmostEqual(figure.axes[1].get_ylim()[1], 3.6)
        output = self.root / "plot.pdf"
        figure.savefig(output)
        self.assertTrue(output.read_bytes().startswith(b"%PDF"))
        self.assertEqual(plot.unique_path(str(output)), str(self.root / "plot1.pdf"))

    def test_command_line_writes_pdf(self):
        path = self.write_csv("cli.csv", "2,10,1000\n2,20,2000\n2,30,3000\n")
        result = subprocess.run(
            [sys.executable, plot.__file__, "--throughput", str(path), "--out", "summary"],
            cwd=self.root, capture_output=True, text=True, check=True,
            env={**os.environ, "MPLBACKEND": "Agg"})
        self.assertIn("3 plotted points from 1 prepared files", result.stdout)
        self.assertTrue((self.root / "summary.pdf").read_bytes().startswith(b"%PDF"))

    def test_reject_mixed_input_modes(self):
        path = self.write_csv("one.csv", "1,2,3\n")
        args = plot.make_parser().parse_args(["--throughput", str(path), "--config1", str(path)])
        with self.assertRaises(SystemExit):
            plot.load_points(args, plot.make_parser(), "throughput")


if __name__ == "__main__":
    unittest.main()
