# Figures for the explainer

The six PNGs here are the charts in `docs/crimguard-explained.pdf`, at presentation
resolution. Drop them straight onto a slide - each already carries its own title.

Everything they show comes from the risk engine, not from hand-drawn numbers.

| File | Shows |
|---|---|
| `case-b.png` | The slow theft: files per day, and the score that climbs anyway |
| `case-a.png` | The same 608-file day with and without an approved ticket |
| `ladder.png` | Every rung of the escalation, 40 through 100 |
| `coverage.png` | 64 of the 100 variables filled, by category |
| `false-positives.png` | Every scored day for five ordinary people |
| `architecture.png` | Browser to website to risk database to engine, and back |

## Regenerating

`risk-data.json` is the engine's own output, exported from `crimguard/risk/scenarios`.
Re-export it if the engine changes, then:

```bash
python docs/figures/make-figures.py   # redraws the six PNGs in place
python docs/figures/make-pdf.py       # rebuilds docs/crimguard-explained.pdf
```

Needs `matplotlib` and `reportlab`. The PDF builds without the PNGs - missing figures
are skipped with a note rather than failing the build.
