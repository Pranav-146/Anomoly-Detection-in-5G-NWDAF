#!/usr/bin/env python3
"""Plot NWDAF threshold-sweep CSV as a simple SVG figure.

No third-party plotting dependency is required; the output is suitable
for reports and can be opened directly in a browser.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def load_detection_rates(path: Path) -> list[tuple[float, float, int]]:
    grouped: dict[float, list[bool]] = defaultdict(list)
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            ratio = float(row["failure_ratio"])
            detected = row["detected"].strip().lower() == "true"
            grouped[ratio].append(detected)

    return [
        (ratio, sum(vals) / len(vals), len(vals))
        for ratio, vals in sorted(grouped.items())
        if vals
    ]


def svg_plot(points: list[tuple[float, float, int]], threshold: float) -> str:
    width, height = 900, 520
    left, right, top, bottom = 88, 48, 48, 84
    plot_w = width - left - right
    plot_h = height - top - bottom

    max_x = max([x for x, _, _ in points] + [threshold, 0.4])
    max_x = max(0.4, max_x)

    def x_pos(x: float) -> float:
        return left + (x / max_x) * plot_w

    def y_pos(y: float) -> float:
        return top + (1.0 - y) * plot_h

    threshold_x = x_pos(threshold)
    poly = " ".join(f"{x_pos(x):.1f},{y_pos(y):.1f}" for x, y, _ in points)

    circles = []
    labels = []
    for x, y, n in points:
        cx, cy = x_pos(x), y_pos(y)
        fill = "#c62828" if y > 0 else "#1565c0"
        circles.append(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="7" fill="{fill}" />'
        )
        labels.append(
            f'<text x="{cx:.1f}" y="{cy - 14:.1f}" text-anchor="middle" '
            f'class="small">{y * 100:.0f}% n={n}</text>'
        )

    x_ticks = []
    for tick in (0.0, 0.1, 0.2, 0.3, 0.4):
        tx = x_pos(tick)
        x_ticks.append(
            f'<line x1="{tx:.1f}" y1="{top + plot_h}" x2="{tx:.1f}" '
            f'y2="{top + plot_h + 6}" stroke="#444" />'
            f'<text x="{tx:.1f}" y="{top + plot_h + 28}" '
            f'text-anchor="middle" class="small">{tick:.2f}</text>'
        )

    y_ticks = []
    for tick in (0.0, 0.5, 1.0):
        ty = y_pos(tick)
        y_ticks.append(
            f'<line x1="{left - 6}" y1="{ty:.1f}" x2="{left}" '
            f'y2="{ty:.1f}" stroke="#444" />'
            f'<text x="{left - 12}" y="{ty + 5:.1f}" '
            f'text-anchor="end" class="small">{tick:.1f}</text>'
        )

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <style>
    text {{ font-family: Arial, sans-serif; fill: #17212b; }}
    .title {{ font-size: 24px; font-weight: 700; }}
    .axis {{ font-size: 15px; font-weight: 700; }}
    .small {{ font-size: 12px; }}
  </style>
  <rect width="100%" height="100%" fill="#ffffff" />
  <text x="{left}" y="30" class="title">NWDAF ABNORMAL_BEHAVIOUR Threshold Sweep</text>
  <line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#17212b" stroke-width="2" />
  <line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#17212b" stroke-width="2" />
  <line x1="{threshold_x:.1f}" y1="{top}" x2="{threshold_x:.1f}" y2="{top + plot_h}" stroke="#c62828" stroke-dasharray="8 8" stroke-width="2" />
  <text x="{threshold_x + 8:.1f}" y="{top + 18}" class="small" fill="#c62828">rule threshold: &gt; {threshold:.2f}</text>
  {"".join(x_ticks)}
  {"".join(y_ticks)}
  <polyline points="{poly}" fill="none" stroke="#263238" stroke-width="3" />
  {"".join(circles)}
  {"".join(labels)}
  <text x="{left + plot_w / 2:.1f}" y="{height - 24}" text-anchor="middle" class="axis">Authentication failure ratio</text>
  <text x="24" y="{top + plot_h / 2:.1f}" text-anchor="middle" class="axis" transform="rotate(-90 24 {top + plot_h / 2:.1f})">Detection rate</text>
</svg>
'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="experiments/nwdaf_threshold_sweep.csv")
    parser.add_argument("--out", default="experiments/nwdaf_threshold_sweep.svg")
    parser.add_argument("--threshold", type=float, default=0.30)
    args = parser.parse_args()

    points = load_detection_rates(Path(args.csv))
    if not points:
        raise SystemExit(f"no rows found in {args.csv}")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(svg_plot(points, args.threshold), encoding="utf-8")
    print(f"wrote {out}")
    for ratio, detection_rate, n in points:
        print(f"ratio={ratio:.4f} detection_rate={detection_rate:.2f} n={n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
