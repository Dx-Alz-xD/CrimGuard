# Charts for the CrimGuard explainer. Every number comes from crimguard/risk/ run for real.
import json, pathlib, textwrap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.patches import FancyBboxPatch, Rectangle
from datetime import datetime

HERE = pathlib.Path(__file__).parent
OUT = HERE
data = json.loads((HERE / 'risk-data.json').read_text())

# Validated reference palette (dataviz skill, light mode, surface #fcfcfb).
SURFACE = '#fcfcfb'
INK = '#0b0b0b'
MUTED = '#52514e'
GRID = '#e3e2df'
S1 = '#2a78d6'   # categorical slot 1, blue
S2 = '#eb6834'   # categorical slot 2, orange
S3 = '#1baf7a'   # categorical slot 3, aqua
GOOD = '#0ca30c'
WARNING = '#fab219'
SERIOUS = '#ec835a'
CRITICAL = '#d03b3b'

plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 8.4,
    'text.color': INK,
    'axes.labelcolor': MUTED,
    'axes.edgecolor': GRID,
    'axes.facecolor': SURFACE,
    'figure.facecolor': SURFACE,
    'xtick.color': MUTED,
    'ytick.color': MUTED,
    'axes.linewidth': 0.7,
    'xtick.major.size': 0,
    'ytick.major.size': 0,
    'legend.frameon': False,
})

D = lambda s: datetime.strptime(s, '%Y-%m-%d')

def tidy(ax, ygrid=True):
    for side in ('top', 'right', 'left'):
        ax.spines[side].set_visible(False)
    ax.spines['bottom'].set_color(GRID)
    if ygrid:
        ax.grid(axis='y', color=GRID, linewidth=0.6, zorder=0)
        ax.set_axisbelow(True)

def bands(ax):
    """The score bands, as recessive background. Status colours, never reused for a series."""
    for lo, hi, c in ((0, 40, GOOD), (40, 70, WARNING), (70, 90, SERIOUS), (90, 100, CRITICAL)):
        ax.axhspan(lo, hi, color=c, alpha=0.065, zorder=0, linewidth=0)

def heading(fig, title, subtitle, x=0.012, y=0.985):
    fig.text(x, y, title, ha='left', va='top', fontsize=10.5, fontweight='bold', color=INK)
    fig.text(x, y - 0.062, subtitle, ha='left', va='top', fontsize=7.8, color=MUTED, linespacing=1.5)

def save(fig, name):
    fig.savefig(OUT / f'{name}.png', dpi=220, facecolor=SURFACE)
    plt.close(fig)
    print('  ', name)

# ---------------------------------------------------------------- 1. Case B
# Two stacked panels sharing the x axis - never a second y scale on one plot.
b = data['caseB']
dates = [D(r['date']) for r in b]
files = [r['files'] for r in b]
score = [r['score'] for r in b]
creep = D(data['caseBcreepStart'])
first_high = D(data['caseBfirstHigh'])
top = max(files) * 1.38

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.4, 4.6), sharex=True,
                               gridspec_kw={'height_ratios': [1, 1.25], 'hspace': 0.18})
fig.subplots_adjust(top=0.84, left=0.09, right=0.985, bottom=0.09)

ax1.axvspan(creep, dates[-1], color=MUTED, alpha=0.05, linewidth=0, zorder=1)
ax1.fill_between(dates, files, color=S1, alpha=0.13, linewidth=0, zorder=2)
ax1.plot(dates, files, color=S1, linewidth=1.5, zorder=3)
ax1.set_ylabel('Files opened per day')
ax1.set_ylim(0, top)
ax1.set_yticks([0, 20, 40, 60, 80])
tidy(ax1)
ax1.axvline(creep, color=MUTED, linewidth=0.9, linestyle=(0, (3, 2)), zorder=4)
ax1.annotate('the creep begins', xy=(creep, top * 0.93), xytext=(6, 0), textcoords='offset points',
             fontsize=7.6, color=MUTED, va='center')
ax1.annotate('about 15 files a day', xy=(dates[55], 42), fontsize=7.8, color=S1,
             fontweight='bold', ha='center')
ax1.annotate('about 70 a day', xy=(dates[-1], top * 0.80), fontsize=7.8, color=S1,
             fontweight='bold', ha='right')

bands(ax2)
ax2.plot(dates, score, color=INK, linewidth=1.7, zorder=3)
ax2.axvline(creep, color=MUTED, linewidth=0.9, linestyle=(0, (3, 2)), zorder=4)
ax2.axvline(first_high, color=CRITICAL, linewidth=1.3, zorder=4)
ax2.annotate('first high-risk day,\n7.5 weeks into the creep', xy=(first_high, 79), xytext=(-16, 16),
             textcoords='offset points', fontsize=7.6, color=CRITICAL, fontweight='bold',
             linespacing=1.4, ha='right',
             arrowprops=dict(arrowstyle='-', color=CRITICAL, linewidth=0.9, shrinkA=2, shrinkB=1))
ax2.set_ylabel('CrimGuard risk score')
ax2.set_ylim(0, 100)
ax2.set_yticks([0, 40, 70, 90, 100])
tidy(ax2)
for y, label in ((18, 'low'), (55, 'medium'), (80, 'high'), (95, 'critical')):
    ax2.annotate(label, xy=(dates[0], y), xytext=(3, 0), textcoords='offset points',
                 fontsize=7, color=MUTED, va='center')
ax2.annotate(f'{score[-1]:.1f}', xy=(dates[-1], score[-1]), xytext=(-3, -13),
             textcoords='offset points', fontsize=8.5, color=INK, fontweight='bold', ha='right')
ax2.xaxis.set_major_formatter(mdates.DateFormatter('%b'))
ax2.xaxis.set_major_locator(mdates.MonthLocator())
heading(fig, 'Case B  -  a slow theft the classic rule never sees',
        'Fifteen files a day becomes seventy over three months. No single day is unusual, so a\n'
        '3-sigma rule stays silent the whole way.')
save(fig, 'case-b')

# ---------------------------------------------------------------- 2. Case A
a = data['caseA']
an = {r['date']: r['score'] for r in data['caseAnoTicket']}
start = data['caseAmigrationStart']
a = [r for r in a if r['date'] >= start][:40]
dA = [D(r['date']) for r in a]
withT = [r['score'] for r in a]
without = [an[r['date']] for r in a]
filesA = [r['files'] for r in a]
mid = dA[len(dA) // 2]

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.4, 4.4), sharex=True,
                               gridspec_kw={'height_ratios': [0.7, 1.3], 'hspace': 0.16})
fig.subplots_adjust(top=0.845, left=0.095, right=0.985, bottom=0.085)

ax1.fill_between(dA, filesA, color=MUTED, alpha=0.1, linewidth=0)
ax1.plot(dA, filesA, color=MUTED, linewidth=1.4)
ax1.set_ylabel('Files per day')
ax1.set_ylim(0, max(filesA) * 1.6)
ax1.set_yticks([0, 400, 800])
ax1.annotate('the very same behaviour drives both lines below', xy=(mid, max(filesA) * 1.34),
             fontsize=7.8, color=MUTED, ha='center')
tidy(ax1)

bands(ax2)
ax2.plot(dA, without, color=S2, linewidth=2.1, zorder=3, label='No ticket on file')
ax2.plot(dA, withT, color=S1, linewidth=2.1, zorder=3, label='Approved migration ticket')
ax2.annotate('no ticket on file  -  96.3, critical', xy=(dA[1], without[0] - 9),
             fontsize=8.4, color=S2, fontweight='bold')
ax2.annotate('approved migration ticket  -  17.8, low', xy=(dA[1], withT[0] + 4),
             fontsize=8.4, color=S1, fontweight='bold')
gx = dA[-8]
ax2.annotate('', xy=(gx, without[-8]), xytext=(gx, withT[-8]),
             arrowprops=dict(arrowstyle='<|-|>', color=MUTED, linewidth=1, shrinkA=1, shrinkB=1))
ax2.annotate('78 points, decided\nby one ticket', xy=(gx, 56), xytext=(-8, 0),
             textcoords='offset points', fontsize=7.8, color=MUTED, ha='right',
             va='center', linespacing=1.4)
ax2.set_ylabel('CrimGuard risk score')
ax2.set_ylim(0, 100)
ax2.set_yticks([0, 40, 70, 90, 100])
tidy(ax2)
ax2.legend(loc='center left', fontsize=7.6, labelcolor=MUTED, bbox_to_anchor=(0.03, 0.52))
ax2.xaxis.set_major_formatter(mdates.DateFormatter('%d %b'))
ax2.xaxis.set_major_locator(mdates.DayLocator(interval=7))
heading(fig, 'Case A  -  the same 608-file day, with and without a reason on file',
        'Context is the whole difference. A classic 3-sigma rule flags both of these identically.')
save(fig, 'case-a')

# ---------------------------------------------------------------- 3. Coverage
cats = [
    ('Access and resources', 10), ('Timing', 10), ('HR and organisation', 10),
    ('Behavioural biometrics', 9), ('Privilege and permission', 7),
    ('Authentication and identity', 6), ('Device and network', 5),
    ('Data movement', 4), ('Communication', 2), ('Physical and environmental', 1),
]
labels = [c[0] for c in cats][::-1]
filled = [c[1] for c in cats][::-1]
rest = [10 - f for f in filled]
y = range(len(labels))

fig, ax = plt.subplots(figsize=(7.4, 3.7))
fig.subplots_adjust(top=0.79, left=0.235, right=0.985, bottom=0.185)
ax.barh(y, filled, color=S1, height=0.6, zorder=3, label='Collected by the website')
ax.barh(y, rest, left=[f + 0.12 for f in filled], color='#c9c8c4', height=0.6, zorder=3,
        label='Needs a system a website is not part of')
for i, f in enumerate(filled):
    ax.annotate(f'{f}', xy=(f - 0.28, i), fontsize=8, color='white', fontweight='bold',
                va='center', ha='right', zorder=4)
ax.set_yticks(list(y))
ax.set_yticklabels(labels, fontsize=8.2, color=INK)
ax.set_xlim(0, 10)
ax.set_ylim(-0.75, 9.6)
ax.set_xticks(range(0, 11, 2))
ax.set_xlabel('Variables in the category (10 each)')
for side in ('top', 'right', 'left'):
    ax.spines[side].set_visible(False)
ax.grid(axis='x', color=GRID, linewidth=0.6)
ax.set_axisbelow(True)
ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.155), ncol=2, fontsize=7.8, labelcolor=MUTED)
heading(fig, '64 of the 100 variables are filled by the website',
        'The other 36 need badge readers, an endpoint agent, device management, a mail gateway or a\n'
        'DLP proxy. They are left blank, never written as zero.')
save(fig, 'coverage')

# ---------------------------------------------------------------- 4. False positives
fig, ax = plt.subplots(figsize=(7.4, 3.2))
fig.subplots_adjust(top=0.79, left=0.09, right=0.985, bottom=0.145)
bands(ax)
for i, u in enumerate(data['ordinary']):
    ys = u['scores']
    xs = [i + 1 + ((hash((i, j)) % 1000) / 1000 - 0.5) * 0.52 for j in range(len(ys))]
    ax.scatter(xs, ys, s=5, color=S1, alpha=0.32, linewidths=0, zorder=3)
    ax.scatter([i + 1], [u['median']], s=40, color=INK, zorder=5, marker='_', linewidths=1.8)
ax.set_xticks(range(1, 6))
ax.set_xticklabels([f"Person {i + 1}\nmedian {u['median']:.1f}" for i, u in enumerate(data['ordinary'])],
                   fontsize=8, color=INK, linespacing=1.5)
ax.set_ylim(0, 100)
ax.set_yticks([0, 40, 70, 90, 100])
ax.set_ylabel('Daily risk score')
ax.set_xlim(0.4, 5.6)
tidy(ax)
ax.axhline(70, color=SERIOUS, linewidth=1, linestyle=(0, (4, 3)), zorder=4)
ax.annotate('not one day out of 1,100 reaches high (70)', xy=(3, 73.5), fontsize=8,
            color=SERIOUS, ha='center', fontweight='bold')
ax.annotate('highest day anyone had: 44', xy=(3, 50), fontsize=7.6, color=MUTED, ha='center')
heading(fig, 'Five ordinary people, about 220 working days each',
        'Every dot is one person on one day. The false-alarm rate decides whether anyone keeps using\n'
        'a detector at all.')
save(fig, 'false-positives')

# ---------------------------------------------------------------- 5. The ladder
# Vertical, so each rung has room for a sentence without colliding with its neighbours.
fig, ax = plt.subplots(figsize=(7.4, 5.4))
fig.subplots_adjust(top=0.85, left=0.02, right=0.98, bottom=0.04)
ax.set_xlim(0, 100)
ax.set_ylim(-4, 104)
ax.axis('off')

BAR_L, BAR_R = 7, 17
for lo, hi, c, name in ((0, 40, GOOD, 'low'), (40, 70, WARNING, 'medium'),
                        (70, 90, SERIOUS, 'high'), (90, 100, CRITICAL, 'critical')):
    ax.add_patch(Rectangle((BAR_L, lo), BAR_R - BAR_L, hi - lo - 0.35, color=c, alpha=0.26, linewidth=0))
    ax.annotate(name, xy=(BAR_L - 1.5, (lo + hi) / 2), fontsize=7.6, color=MUTED,
                ha='right', va='center')

steps = [
    ([100], 'Certainty, not probability',
     'Reserved for a tripped trap. Not a guess about behaviour - a fact about what was touched.'),
    ([90], 'Account frozen',
     'Every session is revoked. Only an admin can let them back in.'),
    ([85], 'Cut again, and a code is asked for',
     'Access drops a second level, and sensitive pages ask for a one-time code.'),
    ([75], 'Access is cut by one level',
     "Everything at or above the library's average confidentiality disappears from their view. "
     'The admin is told, and can switch it off for that person.'),
    ([70], 'Confirm your password',
     'Asked once, before anything sensitive opens.'),
    ([50], 'Confirm your password*',
     'Only when the pattern looks like a stolen account rather than a bad day.'),
    ([40, 60, 80], 'Decoy files appear',
     'Bait named like an API key dump: one at 40, a more tempting one at 60, a third at 80.\n'
     'Nobody legitimate has a reason to open any of them.'),
]
# Thresholds sit 5 points apart in places; the text rows are spaced evenly and joined to the bar by
# leaders, so nothing has to be squeezed in next to its own tick.
TOP_ROW, ROW_GAP, NUM_X, TEXT_X, WRAP = 97.0, 15.0, 23.0, 37.0, 82
for i, (values, title, body) in enumerate(steps):
    ty = TOP_ROW - i * ROW_GAP
    c = CRITICAL if values[0] >= 90 else SERIOUS if values[0] >= 70 else WARNING
    for v in values:
        ax.plot([BAR_R, BAR_R + 2, NUM_X - 4, NUM_X - 2], [v, v, ty, ty],
                color=c, linewidth=1.1, zorder=4, solid_joinstyle='round')
        ax.scatter([BAR_R], [v], s=26, color=c, zorder=5)
    ax.annotate('/'.join(str(v) for v in values), xy=(NUM_X, ty), fontsize=8.6, color=c,
                fontweight='bold', ha='left', va='center')
    ax.annotate(title, xy=(TEXT_X, ty + 1.2), fontsize=8.6, color=INK, fontweight='bold',
                ha='left', va='bottom')
    ax.annotate(textwrap.fill(body, WRAP), xy=(TEXT_X, ty - 1.2), fontsize=7.4, color=MUTED, ha='left', va='top',
                linespacing=1.45)
ax.annotate('* the step-up at 50 is conditional; every other rung is automatic', xy=(7, -3.2),
            fontsize=6.9, color=MUTED, va='center')
heading(fig, 'What happens as the score climbs',
        'Nobody is locked out at the first sign of something odd. The response grows with the evidence.')
save(fig, 'ladder')

# ---------------------------------------------------------------- 6. Architecture
fig, ax = plt.subplots(figsize=(7.4, 3.0))
fig.subplots_adjust(top=0.8, left=0.01, right=0.99, bottom=0.02)
ax.set_xlim(0, 100)
ax.set_ylim(0, 42)
ax.axis('off')

def box(x, y, w, h, title, sub, edge, fill):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.6,rounding_size=1.4',
                                fc=fill, ec=edge, linewidth=1.1, zorder=3))
    ax.annotate(title, xy=(x + w / 2, y + h - 3.2), fontsize=8.2, fontweight='bold',
                color=INK, ha='center', va='center', zorder=4)
    ax.annotate(sub, xy=(x + w / 2, y + h / 2 - 3.4), fontsize=6.9, color=MUTED,
                ha='center', va='center', linespacing=1.5, zorder=4)

# The gaps between boxes are narrower than the labels, so the cadence is written above the row.
def arrow(x1, x2, y, label):
    ax.annotate('', xy=(x2, y), xytext=(x1, y),
                arrowprops=dict(arrowstyle='-|>', color=MUTED, linewidth=1.1, shrinkA=0, shrinkB=0))
    ax.annotate(label, xy=((x1 + x2) / 2, 38.6), fontsize=7, color=MUTED, ha='center', va='center')
    ax.plot([(x1 + x2) / 2, (x1 + x2) / 2], [36.6, 37.4], color=GRID, linewidth=1)

W, H, Y = 19, 20, 16
box(0.5, Y, W, H, 'The browser', 'typing rhythm\npointer speed\nclipboard size\nprinting', S1, '#eaf2fc')
box(27, Y, W, H, 'Red (the website)', 'files opened\nsign-ins\nrole changes\nbytes sent', S1, '#eaf2fc')
box(53.5, Y, W, H, 'The risk database', '100 variables\nper person\nper day', S3, '#e8f7f1')
box(80, Y, W, H, 'The engine', 'one score, 0 to 100\nplus the reason\nfor it', S3, '#e8f7f1')

arrow(20.6, 25.9, Y + H / 2, 'once a minute')
arrow(47.1, 52.4, Y + H / 2, 'every 15 min')
arrow(73.6, 78.9, Y + H / 2, 'scored')

ax.plot([89.5, 89.5, 30, 30], [14.8, 9.5, 9.5, 13.2], color=CRITICAL, linewidth=1.2,
        solid_joinstyle='round', zorder=2)
ax.annotate('', xy=(30, 14.6), xytext=(30, 11.5),
            arrowprops=dict(arrowstyle='-|>', color=CRITICAL, linewidth=1.2, shrinkA=0, shrinkB=0))
ax.annotate('the score comes back and decides what that person can still open,\n'
            'whether a decoy appears, and whether the account is frozen',
            xy=(60, 7.6), fontsize=7, color=CRITICAL, ha='center', va='top', linespacing=1.5)
heading(fig, 'How a click becomes a decision',
        'Nothing here leaves the two databases. The whole loop closes in about fifteen minutes.')
save(fig, 'architecture')

print('done')
