# Builds the CrimGuard explainer PDF.
import pathlib
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (BaseDocTemplate, Frame, Image, KeepTogether, NextPageTemplate,
                                PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

OUT = pathlib.Path(__file__).resolve().parent.parent / 'crimguard-explained.pdf'

RED = colors.HexColor('#c8102e')
TEAL = colors.HexColor('#0d9488')
INK = colors.HexColor('#17191d')
SLATE = colors.HexColor('#5c636e')
LINE = colors.HexColor('#dcdfe4')
WASH = colors.HexColor('#f6f7f9')
REDWASH = colors.HexColor('#fdeef1')
TEALWASH = colors.HexColor('#e6f5f3')

ss = getSampleStyleSheet()

def S(name, **kw):
    base = kw.pop('parent', ss['Normal'])
    return ParagraphStyle(name, parent=base, **kw)

Body = S('Body', fontName='Helvetica', fontSize=9.6, leading=14.4, textColor=INK,
         spaceAfter=7, alignment=TA_LEFT)
Lead = S('Lead', parent=Body, fontSize=11.5, leading=17, textColor=INK, spaceAfter=10)
Small = S('Small', parent=Body, fontSize=8.4, leading=12.2, textColor=SLATE)
Bullet = S('Bullet', parent=Body, leftIndent=12, bulletIndent=2, spaceAfter=4.5)
H1 = S('H1', fontName='Helvetica-Bold', fontSize=21, leading=25, textColor=INK,
       spaceBefore=4, spaceAfter=3)
H2 = S('H2', fontName='Helvetica-Bold', fontSize=14, leading=18, textColor=INK,
       spaceBefore=16, spaceAfter=5)
H3 = S('H3', fontName='Helvetica-Bold', fontSize=10.6, leading=14, textColor=INK,
       spaceBefore=11, spaceAfter=3)
Kicker = S('Kicker', fontName='Helvetica-Bold', fontSize=8, leading=11, textColor=RED,
           spaceAfter=2)
Cell = S('Cell', parent=Body, fontSize=8.8, leading=12.4, spaceAfter=0)
CellB = S('CellB', parent=Cell, fontName='Helvetica-Bold')
CellS = S('CellS', parent=Cell, textColor=SLATE)
Mono = S('Mono', parent=Body, fontName='Courier', fontSize=8.4, leading=12)
Caption = S('Caption', parent=Body, fontSize=8, leading=11.6, textColor=SLATE, spaceAfter=0)

story = []

def P(text, style=Body):
    story.append(Paragraph(text, style))

def bullets(items, style=Bullet):
    for it in items:
        story.append(Paragraph(it, style, bulletText='\u2022'))

def gap(h=6):
    story.append(Spacer(1, h))

def h2(text):
    story.append(Paragraph(text, H2))

def h3(text):
    story.append(Paragraph(text, H3))

def table(rows, widths, header=True, zebra=True, align=None, fs=None):
    data = []
    for r_i, row in enumerate(rows):
        out = []
        for c_i, cell in enumerate(row):
            if isinstance(cell, Paragraph):
                out.append(cell)
            else:
                st = CellB if (header and r_i == 0) else Cell
                out.append(Paragraph(str(cell), st))
        data.append(out)
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign='LEFT')
    style = [
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 7),
        ('RIGHTPADDING', (0, 0), (-1, -1), 7),
        ('LINEBELOW', (0, 0), (-1, -2), 0.4, LINE),
        ('BOX', (0, 0), (-1, -1), 0.6, LINE),
    ]
    if header:
        style += [('BACKGROUND', (0, 0), (-1, 0), WASH),
                  ('LINEBELOW', (0, 0), (-1, 0), 0.9, colors.HexColor('#b9bfc7'))]
    if zebra:
        start = 1 if header else 0
        for i in range(start, len(data)):
            if (i - start) % 2 == 1:
                style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fbfcfd')))
    if align:
        for col, a in align.items():
            style.append(('ALIGN', (col, 0), (col, -1), a))
    t.setStyle(TableStyle(style))
    story.append(t)
    gap(9)

def callout(title, text, tint=REDWASH, bar=RED):
    inner = [[Paragraph(f'<b>{title}</b>', S('ct', parent=Body, fontSize=9.6, textColor=bar, spaceAfter=3)),],
             [Paragraph(text, S('cb', parent=Body, fontSize=9.2, leading=13.6, spaceAfter=0))]]
    t = Table(inner, colWidths=[165 * mm], hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), tint),
        ('LINEBEFORE', (0, 0), (0, -1), 2.6, bar),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 0),
        ('TOPPADDING', (0, 1), (-1, 1), 2),
        ('BOTTOMPADDING', (0, -1), (-1, -1), 9),
    ]))
    story.append(KeepTogether(t))
    gap(10)

FRAME_W = 165 * mm
FIGS = pathlib.Path(__file__).resolve().parent

# Figures are PNGs rendered by figures.py from the engine's own output. A missing file is skipped
# rather than fatal, so the document still builds on a machine that has not run the chart script.
def figure(name, caption, width=FRAME_W, space=11):
    path = FIGS / f'{name}.png'
    if not path.exists():
        print(f'  (missing figure: {name})')
        return
    iw, ih = ImageReader(str(path)).getSize()
    w = min(width, FRAME_W)
    img = Image(str(path), width=w, height=w * ih / iw)
    img.hAlign = 'LEFT'
    story.append(KeepTogether([img, Spacer(1, 4), Paragraph(caption, Caption)]))
    gap(space)

# ---------------------------------------------------------------- page furniture

def cover(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(colors.HexColor('#101216'))
    canvas.rect(0, 0, w, h, stroke=0, fill=1)
    canvas.setFillColor(RED)
    canvas.rect(0, h - 10 * mm, w, 10 * mm, stroke=0, fill=1)
    canvas.setFillColor(TEAL)
    canvas.rect(0, h - 12.4 * mm, w, 2.4 * mm, stroke=0, fill=1)

    canvas.setFillColor(colors.white)
    canvas.setFont('Helvetica-Bold', 44)
    canvas.drawString(22 * mm, h - 78 * mm, 'CrimGuard')
    canvas.setFont('Helvetica', 17)
    canvas.setFillColor(colors.HexColor('#b9c0c9'))
    canvas.drawString(22 * mm, h - 90 * mm, 'How the whole thing works')

    canvas.setStrokeColor(colors.HexColor('#3a4049'))
    canvas.setLineWidth(0.8)
    canvas.line(22 * mm, h - 100 * mm, w - 22 * mm, h - 100 * mm)

    canvas.setFont('Helvetica', 11)
    canvas.setFillColor(colors.HexColor('#9aa2ac'))
    lines = [
        'An insider-threat detection platform built into a working file-sharing site.',
        '',
        'Part 1 explains it with no technical knowledge assumed.',
        'Part 2 explains exactly how each piece works.',
        'Part 3 is a ready-made outline for the slide deck.',
    ]
    y = h - 114 * mm
    for ln in lines:
        canvas.drawString(22 * mm, y, ln)
        y -= 6.6 * mm

    canvas.setFillColor(colors.HexColor('#6c737d'))
    canvas.setFont('Helvetica', 9)
    canvas.drawString(22 * mm, 22 * mm, 'Prepared for the team  |  September 2026')
    canvas.restoreState()

def page(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(RED)
    canvas.rect(0, h - 4 * mm, w, 4 * mm, stroke=0, fill=1)
    canvas.setFont('Helvetica', 7.6)
    canvas.setFillColor(SLATE)
    canvas.drawString(20 * mm, 12 * mm, 'CrimGuard  |  How the whole thing works')
    canvas.drawRightString(w - 20 * mm, 12 * mm, str(canvas.getPageNumber() - 1))
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 16 * mm, w - 20 * mm, 16 * mm)
    canvas.restoreState()

class Doc(BaseDocTemplate):
    # Called for every flowable as it lands, which is the only point the page is actually known.
    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        name = flowable.style.name
        if name not in ('H1', 'H2'):
            return
        text = flowable.getPlainText()
        if text == 'Contents':
            return
        parts = {'In plain English': 'Part 1  -  In plain English',
                 'In detail': 'Part 2  -  In detail',
                 'For the slide deck': 'Part 3  -  For the slide deck'}
        if name == 'H1':
            if text not in parts:
                return
            self.notify('TOCEntry', (0, parts[text], self.page - 1))
        else:
            self.notify('TOCEntry', (1, text, self.page - 1))


doc = Doc(str(OUT), pagesize=A4,
                      leftMargin=20 * mm, rightMargin=20 * mm,
                      topMargin=18 * mm, bottomMargin=22 * mm,
                      title='CrimGuard - How the whole thing works',
                      author='Red / CrimGuard')
frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='f')
doc.addPageTemplates([
    PageTemplate(id='cover', frames=[frame], onPage=cover),
    PageTemplate(id='body', frames=[frame], onPage=page),
])

story.append(NextPageTemplate('body'))
story.append(PageBreak())

# ================================================================= CONTENTS

P('Contents', H1)
gap(4)

toc = TableOfContents()
toc.dotsMinLevel = 0
toc.levelStyles = [
    S('toc0', parent=Body, fontName='Helvetica-Bold', fontSize=10, leading=17,
      spaceBefore=10, textColor=RED),
    S('toc1', parent=Body, fontSize=9.4, leading=14.6, leftIndent=12, firstLineIndent=-12,
      textColor=INK, spaceAfter=0),
]
story.append(toc)

story.append(PageBreak())

# ================================================================= PART 1

P('PART 1', Kicker)
P('In plain English', H1)
P('No technical knowledge assumed. If you only read one part, read this one.', Small)
gap(10)

h2('What problem this solves')
P('Most security spending goes on keeping strangers out: firewalls, passwords, locks on the door. '
  'That does nothing about the far more common and far more expensive problem, which is the person '
  'who is <b>already inside and already allowed in</b>. The employee who copies the customer list on '
  'their way to a competitor. The contractor who downloads the source code the week before their '
  'contract ends. They do not break in. They log in, the way they do every morning.')
P('The hard part is that their activity looks exactly like work, because it <i>is</i> work, right up '
  'until it is not. A person reading 600 files might be doing a database migration or might be '
  'emptying the filing cabinet. Nothing about the number 600 tells you which.')

callout('The problem in one sentence',
        'You cannot catch insider data theft by looking for unusual activity, because unusual activity '
        'is mostly just people doing their jobs. You have to look at whether there is a reason for it.',
        REDWASH, RED)

h2('The two halves: Red and CrimGuard')
P('What we built is two things in one, and keeping them separate in your head makes the rest easy.')

table([
    ['', 'Red', 'CrimGuard'],
    ['What it is', 'A working file-sharing website. Projects, files, teams, logins, permissions.',
     'A security system watching how everyone uses Red.'],
    ['Who sees it', 'Everybody. It is the product people log into and do their work in.',
     'Mostly invisible. Admins get a dashboard; everyone can see their own score.'],
    ['What it does', 'Stores your projects and files. Controls who can open what.',
     'Scores how each person behaves, and narrows or cuts their access when that score climbs.'],
    ['Think of it as', 'The office building.', 'The security desk, the badge system and the cameras.'],
], [24 * mm, 66 * mm, 76 * mm])

P('This matters because the detection is not a separate tool bolted on afterwards. It is built into '
  'the same site people work in, which is why it can see things a bolted-on tool cannot, and why it '
  'can act instantly rather than filing a report for someone to read on Monday.')

gap(4)
figure('architecture',
       'The whole loop. The browser and the website both feed the risk database; the engine turns that '
       'into one number, and the number comes back and changes what the person can do.')

h2('The one idea everything hangs off')
P('Every account has a <b>risk score from 0 to 100</b>, recalculated continuously. It is built from '
  '<b>100 separate signals</b> about how that person behaves: how many files they open, when they work, '
  'how much they download, where they sign in from, even how they type.')
P('Each signal is measured <b>against that person\'s own normal</b>, not against a company-wide rule. '
  'Someone who always works at midnight is not suspicious for working at midnight. Someone who never '
  'has, suddenly is.')

callout('Why "against their own normal" is the whole trick',
        'A rule that says "alert if anyone downloads more than 500MB" fires constantly on the people whose '
        'job is moving data, and never fires on the person whose normal is 5MB and who just took 400. '
        'Comparing each person to themselves fixes both problems at once.',
        TEALWASH, TEAL)

h2('The two cases that define the product')
P('These two situations are the reason the system is shaped the way it is. They are worth memorising, '
  'because they explain every design decision that follows.')

table([
    ['', 'Case A - the false alarm', 'Case B - the real theft'],
    ['What happens',
     'An engineer reads 608 files in one day, up from a normal of 15.',
     'An employee goes from 15 files a day to 70, gradually, over three months.'],
    ['Is there a reason on file?',
     'Yes - an approved migration ticket that expects about 600 files a day.',
     'No ticket, no project, no role change. Nothing.'],
    ['What a traditional tool does',
     'Screams. It is a 40x spike. The analyst investigates, finds nothing, and trusts the tool a little less.',
     'Nothing at all. No single day is unusual, so no threshold is ever crossed.'],
    ['What CrimGuard does',
     '<b>Scores it 17.8 - low.</b> The ticket explains it, and the amount is proportionate to what the ticket expects.',
     '<b>Scores it 72.9 - high.</b> It compares against a frozen snapshot of months ago, not a rolling average that quietly absorbs the creep.'],
], [26 * mm, 70 * mm, 70 * mm])

callout('Say this in the presentation',
        'Traditional monitoring gets both of these exactly backwards: it raises an alarm about the person '
        'doing their job, and stays silent about the person stealing. We flag the second and clear the first. '
        'And if that same engineer had done the identical thing with <i>no</i> ticket on file, the score goes '
        'from 17.8 to 96.3 - critical.',
        REDWASH, RED)

P('The reason Case B is invisible to normal tools is subtle and worth understanding. Most systems compare '
  'you to your recent average. If you creep up slowly, your recent average creeps up with you, so you never '
  'look unusual. CrimGuard also keeps an <b>anchored</b> comparison - a frozen picture of what you were like '
  'three to six months ago - which the creep cannot move. That is what catches it, roughly seven and a half '
  'weeks into the theft.')

story.append(PageBreak())
figure('case-b',
       'Case B, run through the real engine. The top panel is what the person did; the bottom is what '
       'CrimGuard made of it. Every point on both lines is real output, not an illustration.')
figure('case-a',
       'Case A, the same way. Both lines below come from identical behaviour: 608 files a day for a month. '
       'The only difference between them is whether a migration ticket exists.')

story.append(PageBreak())

h2('What happens as someone gets riskier')
P('The response is a ladder, not a switch. Nothing dramatic happens at a low score, and each step up is '
  'proportionate. All of it is automatic.')

figure('ladder', 'Every rung, in order. A person on a bad day drifts into the 40s and meets a decoy '
                 'they have no reason to touch. Losing access needs 75, and a freeze needs 90.')

table([
    ['Score', 'What happens', 'Does the person notice?'],
    ['<b>40</b>', 'A fake file appears among their files, designed to look like exactly what a data '
     'thief would reach for.', 'No. It looks like a real file.'],
    ['<b>50</b>', 'If the pattern looks like a stolen account specifically, they are asked to confirm '
     'their password.', 'Yes - a password prompt.'],
    ['<b>60</b>', 'A second, more tempting fake file appears.', 'No.'],
    ['<b>70</b>', 'They must confirm their password before they can do anything else.', 'Yes.'],
    ['<b>75</b>', '<b>Access narrows.</b> Their clearance drops one level - files they could open '
     'yesterday stop opening. They also cannot upload.', 'Yes, clearly.'],
    ['<b>80</b>', 'A third fake file appears.', 'No.'],
    ['<b>85</b>', 'Access narrows again, by a second level. Separately, they are asked for a '
     'verification code.', 'Yes.'],
    ['<b>90</b>', '<b>The account is frozen.</b> Every session ends and they cannot sign back in '
     'until an admin lets them.', 'Yes. They are locked out.'],
    ['<b>100</b>', 'Reserved for certainty - see the traps below.', 'Locked out.'],
], [14 * mm, 96 * mm, 56 * mm])

P('Two things about this ladder are deliberate. First, <b>the early steps are silent</b>: if someone is '
  'stealing, you do not want to tell them they have been noticed, you want to give them a marked banknote. '
  'Second, <b>an admin can switch the access-narrowing off</b> for a specific person if it is getting in the '
  'way of real work - but an admin cannot switch it off for themselves, or for another admin. Only the CEO '
  'can do that. Otherwise the control would be optional for exactly the people with the most access.')

h2('The traps')
P('This is the part that tends to land best in a presentation, because it is the one place the system stops '
  'guessing and becomes certain.')
P('Once someone looks risky, a <b>fake file appears that only they can see</b>. It is named like the thing '
  'a person stealing data would go for: "Production API keys (do not share)", "Payroll and compensation - '
  'all staff", "Customer master list". It is not real. Nothing legitimate ever needs to touch it.')

table([
    ['If they...', 'What we conclude', 'What happens'],
    ['Open it and look', 'Nothing. Curiosity is not theft, and the file is empty.', 'Nothing.'],
    ['Try to change or delete it', 'They were acting on it, not just looking.',
     'Every session ends instantly, the account is frozen, and the score is pinned at 100.'],
    ['Copy the fake password inside it and paste it somewhere', 'Certainty.',
     'The same, and we know where it went.'],
    ['Try to use the fake password to log in somewhere', 'Certainty, plus whoever used it.',
     'Both accounts frozen.'],
], [38 * mm, 64 * mm, 64 * mm])

callout('Why this is different from everything else in the system',
        'Every other signal is probability - this behaviour is unusual, therefore it might be theft. A trap trip '
        'is not probability. Nobody touches a file that does not exist and was never mentioned by accident. '
        'It is the one signal that needs no context to interpret.',
        TEALWASH, TEAL)

story.append(PageBreak())

h2('What it never records')
P('Expect this question, because it is the first one a thoughtful person asks. The honest answer is good, '
  'and it should be said before anyone has to ask.')

table([
    ['What we DO record', 'What we NEVER record'],
    ['<b>How fast you type</b> - the average gap between keystrokes over a minute, and how long keys are held.',
     '<b>Which keys you pressed.</b> Key identity never leaves your browser. Nothing you type is transmitted or stored.'],
    ['<b>How fast the pointer moves</b>, as an average.',
     '<b>Where the pointer went.</b> No positions, no paths, no clicks.'],
    ['<b>That you copied something</b>, how many characters, and whether it looked like a password or a key.',
     '<b>What you copied.</b> The text is checked inside the page and thrown away. Only the category name survives.'],
    ['<b>Which files and pages you opened</b>, and when.',
     '<b>What is inside your files.</b> The system records that a file was opened and how big it is, never its contents.'],
    ['<b>Sign-ins, the browser, roughly which network</b> you came from.',
     '<b>Your precise location.</b> The network your address belongs to and your browser time zone, nothing finer.'],
], [82 * mm, 84 * mm])

P('Two further points that matter. <b>Everyone can see their own score</b> and all 100 variables behind it, '
  'live, from a button in the corner of every page - because scoring people and hiding it from them would be '
  'worse. And there is a page at <b>/privacy</b> that says all of the above to the people being scored, in '
  'the same plain language.')

callout('The line to use if challenged',
        'We record the rhythm of the typing, not the typing. It is the difference between recognising someone '
        'by their walk and reading their diary.',
        REDWASH, RED)

story.append(PageBreak())

# ================================================================= PART 2

P('PART 2', Kicker)
P('In detail', H1)
P('How each piece actually works. Technical, but written to be readable.', Small)
gap(10)

h2('Architecture: what talks to what')
P('There are two databases, deliberately separate.')

table([
    ['', 'The website database', 'The risk database'],
    ['Holds', 'Accounts, passwords, roles, projects, files, who can see what, the activity log.',
     'The 100 variables per person per day, raw behaviour events, risk scores, alerts, the HR timeline.'],
    ['Engine', 'SQLite, always.', 'PostgreSQL if configured, otherwise a SQLite copy.'],
    ['Why separate', 'It is the product. It must work whether or not anyone is watching.',
     'It is the detection platform, designed to also ingest badge readers, EDR and HR feeds that a website has nothing to do with.'],
], [26 * mm, 70 * mm, 70 * mm])

P('<b>Red runs perfectly without the risk database attached.</b> Detach it and every page behaves '
  'identically; nothing is recorded and nothing is scored. That was a design rule, not an accident - the '
  'security layer is never allowed to be the reason the product breaks.')

h3('The flow, end to end')
table([
    ['1', 'Somebody uses Red', 'They open a file, sign in, type, copy something, download an export.'],
    ['2', 'It is recorded', 'The browser reports what only it can see (typing rhythm, clipboard size). '
     'The server records everything it can see for itself, where a page cannot forge it.'],
    ['3', 'It is aggregated', 'Every 15 minutes, the raw events for each person become one daily snapshot '
     'of 100 numbers.'],
    ['4', 'It is scored', 'The engine turns those 100 numbers into one score from 0 to 100, plus a reason '
     'for every point of it.'],
    ['5', 'Something happens', 'The score is copied back to the website database, where it decides what '
     'that person can still open, whether a trap appears, and whether the account is frozen.'],
], [8 * mm, 40 * mm, 118 * mm], header=False)

callout('An important architectural detail worth a slide',
        'Scores are calculated in the risk database, but access is decided in the website database. So each '
        'score is copied across as it is produced. That is why narrowing someone\'s access is instant and '
        'automatic rather than a nightly batch job.',
        TEALWASH, TEAL)

story.append(PageBreak())

h2('The 100 variables')
P('The catalogue of 100 risk variables is the backbone. Each one has a defined type, a direction that counts '
  'as suspicious, a weight, and a flag saying whether context can ever excuse it. They fall into ten groups.')

table([
    ['Group', 'Filled', 'What it measures'],
    ['Access and resources', '10 / 10', 'Which projects, pages and account records were opened; what was searched for'],
    ['Timing', '10 / 10', 'When someone works, against their own pattern and the company\'s hours'],
    ['Data movement', '4 / 10', 'Exports, printing, clipboard size. No USB, personal cloud or email'],
    ['Authentication and identity', '6 / 10', 'Sign-ins, failures, new devices, new networks and countries, replayed session cookies'],
    ['Device and network', '5 / 10', 'Browser fingerprint, address ranges, impossible travel, bytes served'],
    ['Behavioural biometrics', '9 / 10', 'Typing and pointer rhythm, scrolling, idle time, focus changes, clipboard'],
    ['HR and organisation', '10 / 10', 'Role changes, plus employment details admins record (leaving date, reviews, leave)'],
    ['Communication', '2 / 10', 'Sensitive terms and secret-shaped patterns in the text people write'],
    ['Privilege and permission', '7 / 10', 'Admin actions, and refusals that show someone reaching past their role'],
    ['Physical and environmental', '1 / 10', 'Printing a page with confidential material on screen'],
], [46 * mm, 18 * mm, 102 * mm], align={1: 'CENTER'})

callout('64 of 100 - and why the other 36 are blank, not zero',
        'The missing 36 need systems a website is not part of: badge readers, an endpoint agent, device '
        'management, a mail gateway, a data-loss proxy. Those are written as <b>blank</b>, never as zero, '
        'because "we have no badge reader" and "nobody entered the building" are completely different facts. '
        'A file records the decision for every one of the 100 variables, and the system refuses to start if '
        'that file and the catalogue ever disagree.',
        REDWASH, RED)

P('That last point is worth making in the deck: it is an honesty mechanism. It is very easy for a dashboard '
  'to show a confident zero for something it has never measured. This one cannot.')

gap(4)
figure('coverage',
       'The same table as a picture. Three categories are complete; the thin ones are thin because the '
       'missing signals live in hardware and gateways a website has no view of.')

h2('Where each number comes from')
P('The split between what the browser reports and what the server records is a security decision, not a '
  'convenience one.')

table([
    ['', 'The browser reports', 'The server records'],
    ['What', 'Only what a server cannot possibly see: typing rhythm, pointer speed, scrolling, idle time, '
     'focus changes, clipboard size, printing, screen capture, and the browser\'s description of itself.',
     'Everything it can see for itself: which files were opened, what was searched for, who signed in, who '
     'changed a role, how many bytes were sent.'],
    ['Why', 'A page can lie about anything. So the browser is trusted with as little as possible, and '
     'nothing it sends can name another person - the account comes from the session.',
     'A page cannot forge it. This is the trustworthy half.'],
    ['How often', 'Batched once a minute; every 15 seconds while someone has their own risk panel open.',
     'As it happens.'],
], [18 * mm, 74 * mm, 74 * mm])

h3('A worked example: impossible travel')
P('This is a good one to demo because the arithmetic is obvious and the result is intuitive.')
P('Two sign-ins are compared. Each is placed on the map, the straight-line distance is taken, and that is '
  'divided by the time between them. Over <b>900 km/h</b> across at least <b>400 km</b> is not a journey '
  'anybody made.')

table([
    ['Two sign-ins', 'Distance', 'Implied speed', 'Verdict'],
    ['Berlin, then Lagos 20 minutes later', '5,196 km', '15,589 km/h', '<b>Impossible</b>'],
    ['Paris, then Lagos 45 minutes later', '4,709 km', '6,279 km/h', '<b>Impossible</b> (same time zone!)'],
    ['Berlin, then New York 2 hours later', '6,386 km', '3,193 km/h', '<b>Impossible</b>'],
    ['Berlin, then New York 10 hours later', '6,386 km', '639 km/h', 'A normal flight'],
    ['Amsterdam, then Brussels 1 minute later', '173 km', '10,394 km/h', 'Too close to judge'],
], [58 * mm, 24 * mm, 28 * mm, 52 * mm], align={1: 'RIGHT', 2: 'RIGHT'})

P('The Paris-to-Lagos row is the one worth pointing at. Those two cities are in the <b>same time zone</b>, '
  'so a system comparing time-zone offsets would never see it. And the ten-hour New York row is the reverse '
  'mistake: an offset comparison would flag a perfectly normal flight every single time. Measuring actual '
  'distance and speed gets both right.')

P('There is a guard as well: <b>the network has to have changed too</b>. A VPN moves your address without '
  'moving you, and changing your laptop\'s region setting moves neither. Neither trips this.', Body)

story.append(PageBreak())

h2('How the score is calculated')
P('This is the most technical section. The short version for a slide is: <b>every signal is turned into a '
  'number between 0 and 1 saying how strong the evidence is, multiplied by how much that signal matters and '
  'how valuable the data was, reduced by how well it is explained, and then combined.</b>')

h3('Step 1 - Is this unusual for this person?')
P('For each numeric signal, the last 30 days of that person\'s own history give a typical value and a spread. '
  'Robust statistics are used (median and median-absolute-deviation rather than mean and standard deviation) '
  'because the outliers we are hunting would otherwise drag the "normal" up towards themselves.')
bullets([
    'A brand-new account has no history, so it is judged against <b>people in the same role</b> until it '
    'builds one - blending from peers to self over about ten days.',
    'A separate <b>anchored</b> comparison looks at a frozen window three to six months back, which is what '
    'catches slow creep (Case B).',
    'For yes/no signals, what matters is <b>how rare it is for that person</b>. A first-ever weekend login '
    'is strong evidence. For somebody who works most weekends it is worth nothing.',
])

h3('Step 2 - How much does this signal matter?')
P('Not all signals are equal, and neither is all data.')
table([
    ['Weight', 'Signals'],
    ['Highest (1.0)', 'Data movement, and the strong precursors: compressing before a transfer, personal '
     'cloud, USB, audit-log tampering, impossible travel, session-token reuse, auto-forward rules, access '
     'granted with no ticket'],
    ['High (0.8-0.9)', 'Access and privilege, authentication and device'],
    ['Middle (0.5-0.7)', 'Communication, biometrics, physical, timing'],
    ['Lowest (0.3-0.4)', 'Deliberately noisy ones - application switching, message volume'],
], [32 * mm, 134 * mm])
P('This is multiplied by <b>how valuable the data touched was</b>, on a 1-to-5 scale. The same behaviour '
  'against the payroll database and against a wiki page are not the same event.')

h3('Step 3 - Is there a reason for it?')
P('This is the part that clears Case A, and the part most tools do not have at all. The system looks for a '
  'ledger entry that covers the behaviour - an assigned ticket, a project, a recent role change - and scores '
  'how well it explains what happened, out of four factors:')
table([
    ['Factor', 'Question it answers'],
    ['Reliability', 'Was the ticket approved? A project is weaker than an approved ticket; a role change weaker still.'],
    ['Timing', 'Was the ticket open at the time? Something back-dated after the activity counts for nothing.'],
    ['Scope', 'Were the files touched actually in the ticket\'s scope?'],
    ['Proportionality', 'The ticket expects 600 files. They read 650, which is fine. They read 3,000, which is not.'],
], [30 * mm, 136 * mm])

callout('A ticket is never a full excuse',
        'Explanation is capped at 90%. A legitimate-looking reason can be cover, and the system is built so '
        'that filing a ticket can reduce your score but never zero it. Only the best single explanation counts, '
        'because two weak excuses do not add up to one good one.',
        TEALWASH, TEAL)

story.append(PageBreak())

h3('Step 4 - Combine it all')
bullets([
    '<b>Within a group</b>, signals overlap - a bulk copy raises the file count, the megabytes and the '
    'confidential-file count together - so the second strongest counts half, the third a quarter, and so on.',
    '<b>Across groups</b>, evidence is treated as independent and combined so that several moderate signals '
    'in different areas add up to a strong one.',
    '<b>Sequences</b> are looked for specifically: collect, then stage, then send. Two or three of those '
    'stages on the same day earns an extra penalty on top, because that ordering is what exfiltration '
    'actually looks like.',
    '<b>Over time</b>, each signal keeps its strongest recent value with a three-day half-life, so a '
    'sustained problem counts once rather than resetting every night.',
    '<b>Personal circumstances amplify but never create.</b> A resignation on file, a bad review, a '
    'disciplinary action, or booking most of the remaining holiday at once all multiply existing risk. '
    'If the behaviour score is zero, it stays zero.',
])

callout('The single most important sentence about the scoring',
        'Every point of the final score can be traced back to the exact signal that produced it. The '
        'contributions add up to the total by construction - so the dashboard can always answer "why is this '
        'person at 84?" with a list, not a shrug. A black box nobody can interrogate would not survive '
        'contact with an actual investigation.',
        REDWASH, RED)

h3('Does it work?')
P('Tested against generated data with known answers:')
table([
    ['Scenario', 'A classic 3-sigma tool', 'CrimGuard'],
    ['Case A: 15 to 608 files/day, approved ticket on file', 'Flagged (wrongly)', '<b>17.8 - low</b>, 90% explained'],
    ['The same, with no ticket on file', 'Flagged', '<b>96.3 - critical</b>'],
    ['Case B: 15 to 70 files/day over 90 days, nothing on file', '<b>Missed entirely</b>', '<b>72.9 - high</b>, caught at ~7.5 weeks'],
    ['5 ordinary people over ~220 working days each', '-', 'Median 1-3, zero high-risk days'],
], [62 * mm, 40 * mm, 60 * mm])
P('That last row is the one to keep in your back pocket. A detector that catches everything by crying wolf '
  'is useless; the false-positive rate is the number that decides whether anyone keeps using it.', Small)

gap(4)
figure('false-positives',
       'Every scored day for the five ordinary people. Five clusters, about 1,100 days, and not one of them '
       'crosses into high. The highest single day anyone had was 44.')

h2('Roles, clearance and confidentiality')
P('Two matching 1-to-5 scales. Roles have <b>clearance</b>; files have <b>confidentiality</b>. Your clearance '
  'must reach a file\'s confidentiality.')

table([
    ['Role', 'Clearance', '', 'File level', 'Name'],
    ['Intern', '1', '', '1', 'Open'],
    ['Employee', '2', '', '2', 'Internal (the default for new files)'],
    ['Admin', '4', '', '3', 'Confidential'],
    ['CEO', '5', '', '4', 'Restricted'],
    ['(the CEO can create more)', '1-5', '', '5', 'Secret - CEO only'],
], [34 * mm, 20 * mm, 6 * mm, 18 * mm, 60 * mm], align={1: 'CENTER', 3: 'CENTER'})

h3('Who can open a file')
bullets([
    'Its <b>owner</b> always can, and so can the <b>CEO</b>. Admins can open anything up to Restricted.',
    'Shared with a <b>role</b>: everyone in it can open the file, as long as the role\'s clearance covers the '
    'file\'s level. A Confidential file shared with Employees stays shut to them.',
    'Shared with a <b>person by name</b>: they can open it at any level. This is the deliberate exception, '
    'and it is the one the departure gate later closes.',
    'A file you cannot see returns "not found", so its existence is not given away.',
    '<b>Only the CEO can mark a file Secret</b>, or change who can see one.',
])

callout('One rule, written once',
        'Who can see which file is expressed as a single database rule that every list, every download, every '
        'dialog and the whole dashboard goes through. There is no second copy that can drift out of step - '
        'which is exactly how permission bugs normally happen.',
        TEALWASH, TEAL)

h2('Risk limiting')
P('The automatic narrowing of access. The baseline is the average confidentiality of every file in the '
  'system, rounded down.')

table([
    ['Score', 'Clearance is capped at', 'If the average file is level 3'],
    ['75 and over', 'one level below the average', 'held to level 2'],
    ['85 and over', 'two levels below', 'held to level 1'],
], [28 * mm, 66 * mm, 68 * mm])

P('<b>Only clearance is cut.</b> Owning a file, and having one handed to you by name, are not clearance '
  'decisions and are deliberately left alone. The point is to narrow how <i>wide</i> someone\'s reach is, '
  'not to lock them out of their own work mid-sentence.')

table([
    ['Governance rule', 'Why'],
    ['An admin can waive it for an ordinary person, with a reason.',
     'Real work sometimes needs it, and the reason is logged.'],
    ['An admin <b>cannot</b> waive it for themselves.',
     'Otherwise the control is optional for the people with the most access.'],
    ['An admin <b>cannot</b> waive it for another admin.', 'Same reason. Only the CEO can.'],
], [72 * mm, 94 * mm])

story.append(PageBreak())

h2('Leaving: the departure gate')
P('Risk limiting only cuts clearance, and a file handed to you <b>by name</b> was never a clearance decision '
  '- so limiting leaves it alone. That is the right default, until somebody is leaving. Insider IP theft '
  'clusters in the weeks around departure, and this is the one door limiting does not close.')

P('So inside the last <b>14 days</b> before a leaving date, and only there:')
table([
    ['The person', 'The file', 'What happens'],
    ['Leaving in 14 days or fewer', 'Handed to them by name, <b>above</b> their clearance', 'Refused, with a request to make'],
    ['Leaving', 'Within their clearance, or their own', 'Opens as it always did'],
    ['Not leaving', 'Anything', 'Opens as it always did'],
], [50 * mm, 62 * mm, 54 * mm])

bullets([
    '<b>The file is still listed.</b> Refusing is not hiding - they have to see it to ask for it, and the '
    'refusal carries the request rather than dead-ending.',
    'The request lands in an admin queue with the file, its level, who is asking, their reason and how many '
    'days they have left.',
    '<b>Approving takes the clearance the file needs.</b> An admin cannot approve their way into a Secret file.',
    'An approval is <b>a key to one file and expires after 7 days</b>, so nobody has to remember to take it back.',
    '<b>Reaching for a held file is recorded</b> - in the activity log and as a signal the risk engine sees. '
    'It is the only trace that would otherwise exist of someone trying on the way out.',
])

h2('Downloading above your clearance')
P('A file handed to you by name, or released by an admin, can sit above your clearance. Two rules apply when '
  'you take a copy of one.')

table([
    ['Rule', 'How it works'],
    ['<b>Every download asks for a code.</b>',
     'The download is refused until a verification code is entered. One code is good for one download of that '
     'file, on that session, within 2 minutes. Five wrong codes shut that file on that session. Passes, '
     'failures and lockouts are all logged.'],
    ['<b>Grabbing it instantly raises the score.</b>',
     'A download attempted within <b>5 seconds</b> of being given the file adds <b>+20</b> to the score for '
     '<b>7 days</b>. It is judged on the first attempt, before the code is asked for, so entering the code '
     'cannot hide it. A retry is the same grab, not a second one.'],
], [52 * mm, 114 * mm])

P('The reasoning behind the second rule is worth saying aloud: somebody who is sent a file and opens it '
  'five seconds later was waiting for it. That is not how people work through a shared document; it is how '
  'people collect one.', Small)

story.append(PageBreak())

h2('Decoys, canaries and honeytraps')
P('Two layers, at two different levels of the system.')

h3('Layer 1 - decoy projects')
P('At score <b>40</b>, a fake project appears in that account\'s list. Only they can see it. Opening it does '
  'nothing. <b>Changing or deleting it</b> is the trip: every session ends, the account is frozen, the next '
  'score is pinned at 100, and a report prints to the server console naming the person, their score at that '
  'moment, which decoy and what they did.')

h3('Layer 2 - decoy files with live canaries')
P('More elaborate. The fake file contains <b>freshly minted fake credentials</b> - things that look exactly '
  'like real API keys and passwords. Those are watched for wherever they reappear:')
table([
    ['Where the fake credential turns up', 'What it proves'],
    ['On the clipboard, inside our own pages', 'They copied it.'],
    ['Written into text somewhere else in the system', 'They moved it.'],
    ['Presented as a login to one of our trap endpoints', 'They tried to use it - and we learn who did.'],
], [72 * mm, 94 * mm])

P('A trip freezes <b>everyone involved</b>: the person the decoy was planted for, and whoever presented the '
  'credential. The credentials stay armed even after the decoy is removed, so a copy taken today still '
  'reports itself when it is used next month.')

callout('Why traps are worth a slide of their own',
        'Every other signal is an inference. A trap trip is not. This is the difference between "this person '
        'is behaving unusually" and "this person took something that only exists to be taken" - and it is the '
        'one piece of evidence that survives an argument.',
        REDWASH, RED)

h2('Behavioural biometrics')
P('The system learns how each person types and moves the mouse, and notices when that changes. Answering, in '
  'effect: <b>is the account owner actually the one at the keyboard?</b>')

table([
    ['Step', 'What happens'],
    ['1. Build a profile', 'From the owner\'s own accepted sessions, each measurement gets a typical value '
     'and a spread.'],
    ['2. Compare', 'A new minute of activity is compared feature by feature. Each feature is capped so one '
     'odd measurement cannot decide alone.'],
    ['3. Calibrate', 'The same comparison is run on all the owner\'s own past sessions, so the question '
     'becomes "how far outside their own variation is this?" - which makes a steady typist and an erratic '
     'one comparable.'],
    ['4. Combine', 'Typing and pointer evidence are merged so that two moderate signals that agree add up to '
     'a strong one.'],
], [34 * mm, 132 * mm])

P('Crucially this is judged <b>together with the risk score</b>, because each means something different alone:')
table([
    ['Typing has changed', 'Risk score', 'Conclusion'],
    ['Yes', 'Normal', 'Probably a different person at the keyboard. Ask them to confirm their password.'],
    ['Somewhat', 'Raised', 'An anomaly <i>alongside</i> a physical change. Ask as well.'],
    ['No', 'Raised', 'It is them, and they are doing something unusual. The other controls handle it.'],
], [42 * mm, 30 * mm, 94 * mm])

story.append(PageBreak())

h2('The identity throttle')
P('One place where everything that acts on an account comes together: a score crossing a policy, a change in '
  'typing, a trap trip, failed confirmations. Three actions are possible.')

table([
    ['Action', 'What it does', 'Triggered by'],
    ['<b>Step-up</b>', 'The session can reach nothing but the confirmation prompt until the owner confirms '
     'with their password.', 'Score 70; score 50 if it looks like a stolen account; typing changed'],
    ['<b>Freeze</b>', 'Every session ends and signing in is refused until an admin restores access.',
     'Score 90; any trap trip'],
    ['<b>Revoke</b>', 'Every session ends, but they can sign in again.', 'Lesser events'],
], [24 * mm, 84 * mm, 58 * mm])

bullets([
    'Every action is written to a response log, so state survives a restart and an admin can see exactly what '
    'was done and why.',
    'A policy can be set to <b>require an admin\'s approval</b> before it acts, rather than acting immediately.',
    '<b>Two challenges can be open at once</b> - a score of 87 crosses both the password policy at 70 and the '
    'code policy at 85. Both stay answerable, because two gates that each only allowed their own answer '
    'through would block each other and leave the person with nothing to do but sign out.',
    'Passing the code challenge earns a <b>bounded, expiring discount of 25 points for 12 hours</b>. Proving '
    'who you are answers the most likely innocent explanation for a high score - somebody else is on this '
    'session - but it does not undo what the detectors actually saw, so it can never take an account below '
    'the medium band on its own.',
])

h2('Shadow AI, sign-in cost, email reputation')

h3('Shadow AI')
P('Work leaving the company into an AI model nobody approved. The module is explicit about the limits: a '
  'website can see, with certainty, <b>that a selection was copied out of one of its own documents</b>, how '
  'large it was, which file and project it came from, how confidential that was, and whether it looked '
  'secret-shaped. It cannot see another browser tab, another application, or an extension - and no amount of '
  'JavaScript changes that. The detection is built on what can actually be known.')

h3('A cost on every sign-in attempt')
P('Before any password is checked, the browser must do a small amount of real computation. This is not a '
  'CAPTCHA and does not try to tell a human from a machine - a model that can read distorted text reads it '
  'better than the person it was meant to admit. What it does is make each attempt <b>cost CPU time</b>, '
  'which is the thing large-scale credential stuffing depends on being free. It turns thousands of guesses a '
  'second into a few, and costs an honest person a few hundred milliseconds they never notice.')

h3('Email reputation')
P('Whether an address appears in known breach data, or belongs to a throwaway domain. Small numbers on '
  'purpose: neither is evidence of wrongdoing, so like the HR factors, it can raise existing risk but never '
  'invent it.')

story.append(PageBreak())

h2('How a new person gets access')
P('Two ways access arrives without anyone granting it file by file.')

table([
    ['', 'How it works'],
    ['<b>A project shared with a role</b>',
     'Everyone in that role can see the project\'s files, <b>including ones uploaded later</b> - which is the '
     'whole reason to share a project rather than a file. Clearance still applies: sharing a project with the '
     'interns does not hand them a Secret file inside it.'],
    ['<b>A new account provisioned from its peers</b>',
     'A new intern should not begin with nothing and wait for somebody to notice. The system looks at the '
     'people who already hold that role, counts how many files each was given, and hands the newcomer the '
     'same number - taking the files the most role-mates already have. Bounded twice: never above the role\'s '
     'clearance, and never at all if there are no peers to copy.'],
], [52 * mm, 114 * mm])

h2('What admins see')
table([
    ['Screen', 'What is on it'],
    ['<b>CrimGuard dashboard</b>', 'Everyone with an account: role, projects, files, storage, whether they '
     'are online, and their risk score. Choose someone and their full record opens - every project and file '
     'with its sharing, files shared with them, the devices they are signed in on, their activity and their '
     'risk trend. It refreshes itself while open.'],
    ['<b>Risk console</b>', 'Everyone\'s score, open alerts, and one person\'s full list of 100 variables with '
     'each one\'s contribution to the score. Also where the HR context is recorded.'],
    ['<b>Activity log</b>', 'Sign-ins, role and password changes, changes to who can see a file, downloads of '
     'other people\'s files, and records opened in CrimGuard. Streams into a live console view.'],
    ['<b>Access requests</b>', 'The queue of people asking for a file the departure gate is holding.'],
    ['<b>Everyone\'s own panel</b>', 'A button in the corner of every page showing that person their own score '
     'and all 100 variables, live.'],
], [40 * mm, 126 * mm])

callout('Two restraints worth mentioning',
        'File names above the viewer\'s clearance are <b>counted but never shown</b>, so an admin can see that '
        'somebody holds Secret files without learning what they are. And <b>looking is itself recorded</b> - '
        'opening someone\'s record goes in the activity log. A system holding everyone\'s risk record has to '
        'watch its own watchers.',
        TEALWASH, TEAL)

story.append(PageBreak())

# ================================================================= PART 3

P('PART 3', Kicker)
P('For the slide deck', H1)
P('Numbers, an outline, and the questions to expect.', Small)
gap(10)

h2('The numbers worth quoting')
table([
    ['100', 'risk variables in the catalogue'],
    ['64', 'of them filled by the website; the other 36 need hardware or systems a website is not part of'],
    ['10', 'categories, from file access to typing rhythm to HR context'],
    ['0-100', 'the risk score, recalculated every 15 minutes and on demand'],
    ['17.8 vs 96.3', 'the same 608-file day, with and without a ticket on file'],
    ['72.9', 'the slow-creep theft that a 3-sigma rule scores 0.5 and ignores completely'],
    ['7.5 weeks', 'how far into a three-month slow theft it is caught'],
    ['0', 'high-risk days across five ordinary users over ~220 working days each'],
    ['900 km/h', 'the impossible-travel threshold'],
    ['75 / 85 / 90', 'access narrowed, narrowed again, account frozen'],
    ['14 days', 'the departure window before someone leaves'],
    ['270', 'automated tests, all passing'],
    ['0', 'third-party packages - no npm dependencies at all'],
], [30 * mm, 136 * mm], header=False, zebra=True)

P('That last one is worth a mention. The whole thing runs on what is built into the language, which means '
  'nothing in the supply chain to compromise and nothing to keep patching - in a security product, that is '
  'a claim worth making.', Small)

story.append(PageBreak())

h2('A suggested 14-slide outline')
table([
    ['#', 'Slide', 'The one thing it says'],
    ['1', 'Title', 'CrimGuard - catching the theft that comes from inside'],
    ['2', 'The problem', 'Security spending keeps strangers out. The expensive problem is the person already '
     'inside and already allowed in.'],
    ['3', 'Why it is hard', 'Their activity looks exactly like work, because it is work - right up until it '
     'is not.'],
    ['4', '<b>Case A and Case B</b>', 'Traditional tools flag the engineer doing their job and miss the person '
     'stealing. Show both columns. <i>This is your strongest slide.</i>'],
    ['5', 'The idea', 'One score, 0-100, from 100 signals, each measured against that person\'s own normal.'],
    ['6', 'What we measure', 'The ten categories. Mention 64 of 100, and that the rest are honestly blank '
     'rather than fake zeros.'],
    ['7', 'Context is the product', 'The four questions asked of any excuse: approved? in time? in scope? '
     'proportionate? Capped at 90% - a ticket can be cover.'],
    ['8', '<b>The ladder</b>', 'The escalation table: 40 bait, 70 confirm, 75 narrow, 85 narrow again, 90 '
     'freeze. Automatic and proportionate.'],
    ['9', '<b>The traps</b>', 'A fake file only they can see. Touch it and you are frozen. The one signal '
     'that is certainty, not probability.'],
    ['10', 'Knowing it is really them', 'Typing and pointer rhythm, judged together with the score. Three '
     'rows of the truth table.'],
    ['11', 'Leaving', 'Theft clusters around departure. The 14-day gate, and the request queue.'],
    ['12', '<b>Privacy</b>', 'The two-column do/do-not table. "The rhythm of the typing, not the typing." '
     'Everyone can see their own score.'],
    ['13', 'Does it work?', 'The results table, and especially the zero false alarms over 1,100 ordinary '
     'user-days.'],
    ['14', 'Close', 'Every point of every score traces back to the signal that produced it.'],
], [8 * mm, 36 * mm, 122 * mm])

story.append(PageBreak())

h2('The figures, ready to drop into slides')
P('Every chart in this document is saved as a PNG in <font face="Courier">docs/figures/</font> in the '
  'repository, at presentation resolution. Drag them straight onto a slide - none of them needs a caption '
  'beyond the title already printed on the image.')
table([
    ['File', 'Use it on', 'What to say over it'],
    ['case-b.png', 'Slide 4', 'Point at the top line first: nothing here looks wrong on any single day. '
     'Then the bottom line: the score climbs anyway.'],
    ['case-a.png', 'Slide 4 or 7', 'Both lines are the same person doing the same thing. One ticket is the '
     'whole difference between 17.8 and 96.3.'],
    ['ladder.png', 'Slide 8', 'Read it bottom to top. Nobody loses anything until 75.'],
    ['coverage.png', 'Slide 6', '64 filled, 36 honestly blank. The blanks are a feature.'],
    ['false-positives.png', 'Slide 13', 'About 1,100 ordinary working days. Not one alarm.'],
    ['architecture.png', 'Slide 5', 'One loop: watch, score, act. It closes in about fifteen minutes.'],
], [34 * mm, 21 * mm, 111 * mm])
P('The charts were generated by running the risk engine itself, not drawn by hand. If the engine changes, '
  're-running the chart script redraws them from the new output.', Small)

story.append(PageBreak())

h2('Lines that land')
bullets([
    '"We are not trying to keep people out. Everyone here is already allowed in. That is the problem."',
    '"A 40x spike with an approved ticket behind it scores 17.8. The same spike with nothing behind it '
    'scores 96.3. The behaviour is identical - the context is not."',
    '"The theft that actually happens is not a spike. It is a creep. Fifteen files a day becomes seventy '
    'over three months, and no single day is ever unusual."',
    '"We record the rhythm of the typing, not the typing."',
    '"Nobody touches a file that does not exist and was never mentioned to them by accident."',
    '"Every point of the score can be traced to the signal that produced it. If you cannot explain a score, '
    'you cannot act on it."',
    '"An admin can turn the restriction off for you. They cannot turn it off for themselves."',
])

h2('Questions to expect')
table([
    ['Question', 'Answer'],
    ['"Is this spyware?"',
     'It records rhythm and counts, never content. No keystrokes, no pointer paths, no file contents, no '
     'clipboard text. Everyone can read their own full record at any time, and there is a page explaining all '
     'of it to them. Detach one database and nothing is recorded at all.'],
    ['"What if it is wrong about someone?"',
     'Nothing irreversible happens automatically. The early steps are silent, the middle ones ask you to '
     'confirm who you are, and an admin can waive the restriction with a reason. A freeze needs an admin to '
     'lift it - which means a human looks at it.'],
    ['"Could an admin abuse this?"',
     'An admin cannot waive their own restriction or another admin\'s - only the CEO can. Looking at someone\'s '
     'record is itself logged. File names above your clearance are counted but never shown to you.'],
    ['"What stops someone gaming it?"',
     'The browser is trusted with as little as possible, and nothing it sends can name another person. '
     'Everything the server can observe for itself is recorded server-side where a page cannot forge it. And '
     'a ticket never explains more than 90% of anything.'],
    ['"Why not buy this?"',
     'Commercial tools are built around one signal each, they alert rather than act, and they mostly cannot '
     'see context. This scores 100 signals together, weighs them against the reason on file, and narrows '
     'access by itself rather than emailing somebody.'],
    ['"How do you know it works?"',
     'Both cases from the pitch reproduce on demand, 270 automated tests pass, and across five ordinary '
     'simulated users over roughly 220 working days each there were zero high-risk days.'],
], [40 * mm, 126 * mm])

gap(12)
P('This document was generated from the working code, not from a plan. Every number in it was taken from '
  'the running system.', Small)

doc.multiBuild(story)
print(f'wrote {OUT} ({OUT.stat().st_size // 1024} KB)')
