"""Build the CareRoute hackathon deck (10 slides, 16:9) — Team Tech Head.

Run:  python3 deck/build_deck.py
Out:  deck/CareRoute_Hackathon_Deck_TeamTechHead.pptx
"""
import os
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.dml import MSO_LINE_DASH_STYLE as DASH
from pptx.util import Pt
from pptx.oxml.ns import qn
from deckkit import (Deck, rgb, ELECTRIC, ORANGE, MAGENTA, PURPLE, MINT, YELLOW,
                     BLACK, WHITE, BLUE_TINT, ORANGE_TINT, MAGENTA_TINT, PURPLE_TINT,
                     MINT_TINT, YELLOW_TINT, GREY_LINE, INK_SOFT, HEAD, BODY, SW, SH, M,
                     Inches)

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
OUT = os.path.join(HERE, "CareRoute_Hackathon_Deck_TeamTechHead.pptx")

d = Deck()


def translucent(shape, pct):
    """set solid-fill transparency (pct = 0..100 opaque->transparent)."""
    sfill = shape.fill._xPr.find(qn("a:solidFill"))
    clr = sfill.find(qn("a:srgbClr"))
    a = clr.makeelement(qn("a:alpha"), {"val": str(int((100 - pct) * 1000))})
    clr.append(a)


def bullets(items, bcolor, tcolor=BLACK, size=9.8, gap=3, bold=False, glyph="•  "):
    out = []
    for it in items:
        out.append({"runs": [{"t": glyph, "size": size, "color": bcolor, "bold": True},
                             {"t": it, "size": size, "color": tcolor, "bold": bold}],
                    "space_after": gap})
    return out


def checkrow(x, y, w, items, size=9.6, tcolor=BLACK, row_h=0.30, circle=MINT):
    for i, it in enumerate(items):
        yy = y + i * row_h
        d.oval(x, yy + 0.02, 0.20, 0.20, fill=circle)
        d.icon("check", x + 0.10, yy + 0.12, 0.13, WHITE)
        d.text(x + 0.28, yy, w - 0.28, row_h,
               [{"t": it, "size": size, "color": tcolor}], anchor="middle",
               name=f"check:{it[:24]}")


# =====================================================================  1
def slide1():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=ELECTRIC)
    # decor
    d.oval(11.2, -1.6, 3.6, 3.6, fill=None, line=PURPLE, lw=2.5)
    d.oval(-1.1, 5.9, 2.6, 2.6, fill=None, line=PURPLE, lw=2.0)
    d.oval(12.30, 6.05, 0.16, 0.16, fill=YELLOW)
    d.oval(12.54, 6.29, 0.09, 0.09, fill=MAGENTA)
    # hero visual (right)
    d.picture(os.path.join(ASSETS, "hero_norm.png"), 7.05, 0.62, 5.73, 3.20)
    d.text(7.05, 3.86, 5.73, 0.36,
           [{"t": "Emergency coordination, visualised: requests, compatible beds, verified priority.",
             "size": 9.0, "color": "C9D2F7", "italic": True}])
    # quick-fact chips under visual
    facts = [("3", "role-based workspaces", WHITE, WHITE),
             ("5", "seeded demo hospitals", ORANGE, BLACK),
             ("3", "bed states tracked", MINT, BLACK)]
    fx = 7.05
    for num, lab, bg, tc in facts:
        d.rrect(fx, 4.28, 1.83, 0.78, fill=None, line=bg, lw=1.4, rad=0.16)
        d.text(fx + 0.14, 4.36, 0.5, 0.6, [{"t": num, "size": 22, "color": bg, "bold": True}],
               anchor="middle")
        d.text(fx + 0.62, 4.34, 1.16, 0.66,
               [{"t": lab, "size": 8.6, "color": WHITE, "bold": True, "line": 1.0}],
               anchor="middle")
        fx += 1.95
    d.pill(7.05, 5.24, 5.73, 0.34, fill=None, line=MAGENTA, lw=1.2)
    d.icon("alert", 7.26, 5.41, 0.18, MAGENTA)
    d.text(7.46, 5.24, 5.2, 0.34,
           [{"t": "Prototype on seeded demo data — not a live hospital feed",
             "size": 9.2, "color": WHITE, "bold": True}], anchor="middle")

    # brand row
    d.pill(M, 0.46, 1.58, 0.32, fill=YELLOW)
    d.text(M, 0.46, 1.58, 0.32, [{"t": "TEAM TECH HEAD", "size": 9.0, "color": BLACK,
                                  "bold": True, "align": "center"}], anchor="middle",
           check=False)
    d.text(2.26, 0.46, 4.6, 0.32,
           [{"t": "HEALTHCARE TECHNOLOGY  ·  EMERGENCY COORDINATION  ·  HOSPITAL MANAGEMENT",
             "size": 8.4, "color": "C9D2F7", "bold": True}], anchor="middle", check=False)
    # emergency indicator
    d.pill(M, 0.98, 2.86, 0.38, fill=MAGENTA)
    d.icon("alert", M + 0.24, 1.17, 0.20, WHITE)
    d.text(M + 0.42, 0.98, 2.4, 0.38,
           [{"t": "EMERGENCY BED COORDINATION", "size": 9.6, "color": WHITE, "bold": True}],
           anchor="middle", check=False)
    # title
    d.text(M, 1.46, 6.4, 1.05, [{"t": "CareRoute", "size": 62, "color": WHITE, "bold": True,
                                 "font": HEAD}], name="title")
    d.rect(M + 0.02, 2.52, 1.5, 0.075, fill=ORANGE)
    d.text(M, 2.68, 6.4, 0.46, [{"t": "Smarter Emergency Bed Coordination", "size": 20,
                                 "color": ORANGE, "bold": True}], name="subtitle")
    # problem panel
    d.rrect(M, 3.42, 6.35, 1.56, fill=ORANGE, rad=0.08)
    d.pill(M + 0.22, 3.58, 1.16, 0.28, fill=BLACK)
    d.text(M + 0.22, 3.58, 1.16, 0.28, [{"t": "THE PROBLEM", "size": 8.8, "color": YELLOW,
                                         "bold": True, "align": "center"}], anchor="middle",
           check=False)
    d.text(M + 0.22, 3.94, 5.92, 0.94,
           [{"t": "During medical emergencies, patients and caregivers may struggle to identify "
                  "suitable hospitals with available beds and the appropriate level of care. "
                  "Fragmented information about availability, capacity and emergency priority "
                  "makes coordination difficult.",
             "size": 10.6, "color": BLACK, "line": 1.06}], name="problem")
    # solve / solution cards
    d.rrect(M, 5.14, 3.10, 1.28, fill=WHITE, rad=0.10)
    d.text(M + 0.18, 5.26, 2.76, 0.26, [{"t": "WHAT WE ARE SOLVING", "size": 9,
                                         "color": ELECTRIC, "bold": True}])
    d.text(M + 0.18, 5.54, 2.76, 0.80,
           [{"t": "Coordinating emergency bed requests with suitable hospital capacity, care "
                  "requirements and verified priority.", "size": 9.4, "color": INK_SOFT,
             "line": 1.05}], name="solving")
    d.rrect(3.80, 5.14, 3.10, 1.28, fill=MINT, rad=0.10)
    d.text(3.98, 5.26, 2.76, 0.26, [{"t": "OUR SOLUTION", "size": 9, "color": BLACK,
                                     "bold": True}])
    d.text(3.98, 5.54, 2.76, 0.80,
           [{"t": "A structured workflow: emergency requests, compatible hospital "
                  "recommendations, operator verification, reservations, arrival tracking.",
             "size": 9.4, "color": BLACK, "line": 1.05}], name="solution1")
    # team strip
    d.text(M, 6.56, 2.0, 0.30, [{"t": "TEAM TECH HEAD", "size": 9.6, "color": YELLOW,
                                 "bold": True}], anchor="middle", check=False)
    team = [("TJ", "Tanay Jorihar", ORANGE, BLACK), ("PV", "Puneet Kumar Verma", MAGENTA, WHITE),
            ("SS", "Shraddha Shetty", MINT, BLACK), ("LB", "Lalit Bist", YELLOW, BLACK)]
    tx = 2.10
    for ini, name, bg, tc in team:
        d.oval(tx, 6.52, 0.34, 0.34, fill=bg)
        d.text(tx, 6.52, 0.34, 0.34, [{"t": ini, "size": 9.5, "color": tc, "bold": True,
                                       "align": "center"}], anchor="middle", check=False)
        d.text(tx + 0.40, 6.52, 1.5, 0.34, [{"t": name, "size": 9.0, "color": WHITE,
                                             "bold": True}], anchor="middle", check=False)
        tx += 0.40 + 1.52
    d.footer(dark=True)
    d.notes(
        "Open with the hook: in an emergency, finding ANY bed is not the problem — finding the "
        "RIGHT bed, with the right care level, through a fair and controlled process is. CareRoute "
        "is our prototype for exactly that. We are Team Tech Head: Tanay Jorihar, Puneet Kumar "
        "Verma, Shraddha Shetty and Lalit Bist. In one line: patients submit emergency bed "
        "requests, CareRoute recommends compatible hospitals, operators verify priority, and the "
        "system tracks holds, reservations and occupancy. Note upfront that this is a seeded "
        "prototype — five demo hospitals — so judges know exactly what they are seeing.")


# =====================================================================  2
def slide2():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=WHITE)
    d.rect(0, 0, SW, 0.16, fill=ELECTRIC)
    top = d.header("01  ·  THE REAL-WORLD PROBLEM", MAGENTA, MAGENTA,
                   "When Every Minute Matters, Coordination Matters",
                   "The coordination gaps CareRoute is designed to close.")
    cards = [
        ("pin", MAGENTA, "Hard to find the right bed",
         "Patients may struggle to identify hospitals with suitable available beds."),
        ("cross", ORANGE, "Care levels differ",
         "General beds, ICU beds and ventilator needs require different levels of care."),
        ("chart", PURPLE, "Capacity must count",
         "Availability and capacity must be considered when recommending a hospital."),
        ("bolt", MAGENTA, "Requests compete",
         "Multiple emergency requests can compete for the same limited capacity."),
        ("alert", ORANGE, "Unverified severity",
         "Unverified severity claims can complicate fair prioritization."),
        ("flow", PURPLE, "Confusing journeys",
         "Uncoordinated request handling can make the patient journey confusing."),
    ]
    cw, ch, gx, gy = 4.013, 1.52, 0.10, 0.12
    y0 = top + 0.10
    for i, (ic, col, t, body) in enumerate(cards):
        x = M + (i % 3) * (cw + gx)
        y = y0 + (i // 3) * (ch + gy)
        d.rrect(x, y, cw, ch, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.07)
        d.rect(x, y + 0.14, 0.075, ch - 0.28, fill=col)
        d.oval(x + 0.26, y + 0.24, 0.52, 0.52, fill=None, line=col, lw=1.6)
        d.icon(ic, x + 0.52, y + 0.50, 0.26, col)
        d.text(x + 0.94, y + 0.26, cw - 1.12, 0.34, [{"t": t, "size": 12.5, "color": BLACK,
                                                      "bold": True}], anchor="middle",
               name=f"s2t{i}")
        d.text(x + 0.28, y + 0.82, cw - 0.56, 0.62, [{"t": body, "size": 9.6,
                                                      "color": INK_SOFT, "line": 1.05}],
               name=f"s2b{i}")
    # journey strip
    jy = y0 + 2 * ch + gy + 0.16
    nodes = [("person", MAGENTA, "Patient in emergency"), ("pin", ORANGE, "Hospital search"),
             ("shieldcheck", PURPLE, "Priority & capacity check"),
             ("bed", MINT, "Bed confirmation")]
    nw = 2.62
    jx = M + 0.35
    for i, (ic, col, lab) in enumerate(nodes):
        d.pill(jx, jy, nw, 0.46, fill=WHITE, line=col, lw=1.4)
        d.icon(ic, jx + 0.30, jy + 0.23, 0.22, col)
        d.text(jx + 0.52, jy, nw - 0.60, 0.46, [{"t": lab, "size": 9.6, "color": BLACK,
                                                "bold": True}], anchor="middle", check=False)
        if i < 3:
            d.harrow(jx + nw + 0.03, jy + 0.15, 0.30, GREY_LINE, th=0.16)
        jx += nw + 0.36
    # insight band
    by = jy + 0.66
    d.rrect(M, by, 12.233, 1.00, fill=ELECTRIC, rad=0.10)
    d.rect(M, by + 0.12, 0.09, 0.76, fill=MAGENTA)
    d.pill(M + 0.30, by + 0.14, 1.34, 0.28, fill=YELLOW)
    d.text(M + 0.30, by + 0.14, 1.34, 0.28, [{"t": "CORE INSIGHT", "size": 8.8, "color": BLACK,
                                              "bold": True, "align": "center"}],
           anchor="middle", check=False)
    d.text(M + 0.30, by + 0.46, 11.6, 0.50,
           [{"t": "Finding an available bed is not enough. The bed must be compatible, available, "
                  "and allocated through a controlled workflow.",
             "size": 14.5, "color": WHITE, "bold": True}], anchor="middle", name="insight")
    d.footer()
    d.notes(
        "Frame the pain without inventing numbers: these are coordination problems, not statistics. "
        "Six gaps: discovery of suitable beds, different care levels for general/ICU/ventilator, "
        "capacity awareness, competing requests, unverified severity claims, and uncoordinated "
        "handling that confuses patients. Walk the journey strip left to right, then land the core "
        "insight: availability alone is insufficient — compatibility, availability and a controlled "
        "allocation workflow must come together. That sentence is the thesis of the whole deck.")


# =====================================================================  3
def slide3():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=WHITE)
    d.rect(0, 0, SW, 0.16, fill=ELECTRIC)
    top = d.header("02  ·  OUR SOLUTION", ORANGE, ORANGE,
                   "One Coordinated Workflow for Emergency Bed Requests",
                   "From the first request to arrival confirmation — one structured, role-based flow.",
                   title_size=27)
    steps = [
        ("person", MAGENTA, "Submit request",
         "Patient or requester submits an emergency request."),
        ("doc", ORANGE, "Request details",
         "Patient ID, descriptive location, severity, required care type."),
        ("gear", PURPLE, "Evaluate fit",
         "Compatibility, availability, distance and capacity."),
        ("shieldcheck", ELECTRIC, "Verify severity",
         "Hospital operator reviews and verifies priority."),
        ("bed", ORANGE, "Allocate bed",
         "Temporary hold, reservation, rejection or release."),
        ("check", MINT, "Track & arrive",
         "Arrival confirmed; request tracked in the workspace."),
    ]
    sw, sh_, gap = 1.845, 1.50, 0.20
    x0 = M + (12.233 - (6 * sw + 5 * gap)) / 2
    sy = top + 0.06
    for i, (ic, col, t, body) in enumerate(steps):
        x = x0 + i * (sw + gap)
        d.rrect(x, sy, sw, sh_, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.09)
        d.oval(x + 0.14, sy + 0.14, 0.40, 0.40, fill=col)
        d.text(x + 0.14, sy + 0.14, 0.40, 0.40, [{"t": str(i + 1), "size": 13, "color": WHITE,
                                                  "bold": True, "align": "center"}],
               anchor="middle", check=False)
        d.icon(ic, x + sw - 0.36, sy + 0.34, 0.26, col)
        d.text(x + 0.14, sy + 0.64, sw - 0.28, 0.30, [{"t": t, "size": 11, "color": BLACK,
                                                       "bold": True}], name=f"s3t{i}")
        d.text(x + 0.14, sy + 0.94, sw - 0.26, 0.56, [{"t": body, "size": 8.6,
                                                       "color": INK_SOFT, "line": 1.02}],
               name=f"s3b{i}")
        if i < 5:
            d.harrow(x + sw + 0.025, sy + sh_ / 2 - 0.08, gap - 0.05, ELECTRIC, th=0.16)
    # workspaces
    wy = sy + sh_ + 0.28
    ws = [
        ("person", ELECTRIC, WHITE, "Patient workspace",
         ["Submit an emergency request", "Request a suitable hospital",
          "Track the request through its states"]),
        ("shieldcheck", ORANGE, BLACK, "Hospital operator workspace",
         ["Review incoming requests", "Verify severity", "Accept or reject requests",
          "Manage reservation & arrival states"]),
        ("gear", PURPLE, WHITE, "Administrator workspace",
         ["Manage demo requests & management functions", "View emergency records",
          "Reset demo emergency data"]),
    ]
    for i, (ic, col, tc, t, items) in enumerate(ws):
        x = M + i * (4.013 + 0.10)
        d.rrect(x, wy, 4.013, 2.62, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.06)
        d.shape(MSO_SHAPE.ROUND_2_SAME_RECTANGLE, x, wy, 4.013, 0.52, fill=col, rad=0.14)
        d.icon(ic, x + 0.34, wy + 0.26, 0.26, tc)
        d.text(x + 0.60, wy, 3.3, 0.52, [{"t": t, "size": 12.5, "color": tc, "bold": True}],
               anchor="middle", check=False)
        d.text(x + 0.26, wy + 0.68, 3.55, 1.86, bullets(items, col, size=9.8, gap=5),
               name=f"s3w{i}")
    d.pill(M, wy + 2.74, 12.233, 0.34, fill=BLUE_TINT)
    d.icon("lock", M + 0.24, wy + 2.91, 0.18, ELECTRIC)
    d.text(M + 0.44, wy + 2.74, 11.6, 0.34,
           [{"t": "Role-based by design — each role gets its own workspace and only the actions "
                  "it is permitted to perform.", "size": 9.6, "color": ELECTRIC, "bold": True}],
           anchor="middle", check=False)
    d.footer()
    d.notes(
        "Walk the six-step flow left to right: submit, capture details (patient ID, descriptive "
        "location, severity, care type), evaluate compatibility/availability/distance/capacity, "
        "operator verification, allocation with holds/reservations/rejections, then tracking and "
        "arrival confirmation. Then the three workspaces: patients submit and track; hospital "
        "operators review, verify severity, accept or reject, and manage reservation and arrival "
        "states for their hospital; administrators manage demo requests, view emergency records and "
        "reset demo data. Emphasise the bottom line: permissions are role-scoped by design.")


# =====================================================================  4
def slide4():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=WHITE)
    d.rect(0, 0, SW, 0.16, fill=PURPLE)
    top = d.header("03  ·  WHAT IS NEW & INNOVATIVE", PURPLE, PURPLE,
                   "Beyond Availability: Priority-Aware Bed Coordination",
                   "Six mechanisms implemented in the prototype — three carry the core innovation.")
    feats = [
        ("cross", "Compatibility Matching",
         "Requests carry a required care type; matching respects the level of care the patient "
         "actually needs.",
         [("General", WHITE, BLACK), ("ICU", WHITE, BLACK), ("Ventilator", WHITE, BLACK)]),
        ("shieldcheck", "Verified Priority",
         "Critical, Urgent and Stable/unverified tiers, FIFO ordering for ties. Self-reported "
         "Critical alone does not raise priority.",
         [("Critical", MAGENTA, WHITE), ("Urgent", WHITE, BLACK),
          ("Stable / unverified", WHITE, BLACK)]),
        ("lock", "Protected Reservations",
         "Temporary holds carry a five-minute expiry; confirmed reservations and occupied beds "
         "are protected from reclamation.",
         [("5-min expiry", MINT, BLACK), ("Confirmed = protected", MINT, BLACK)]),
    ]
    fy = top + 0.06
    for i, (ic, t, body, chips) in enumerate(feats):
        x = M + i * (4.013 + 0.10)
        d.rrect(x, fy, 4.013, 2.42, fill=ORANGE, rad=0.07)
        d.oval(x + 0.24, fy + 0.22, 0.56, 0.56, fill=BLACK)
        d.icon(ic, x + 0.52, fy + 0.50, 0.30, YELLOW)
        d.text(x + 0.96, fy + 0.22, 2.9, 0.56, [{"t": t, "size": 14.5, "color": BLACK,
                                                 "bold": True}], anchor="middle",
               name=f"s4t{i}")
        d.text(x + 0.24, fy + 0.94, 3.55, 0.92, [{"t": body, "size": 9.8, "color": BLACK,
                                                  "line": 1.06}], name=f"s4b{i}")
        cx = x + 0.24
        for lab, bg, tc in chips:
            wch = 0.16 + len(lab) * 0.062
            d.pill(cx, fy + 1.94, wch, 0.28, fill=bg)
            d.text(cx, fy + 1.94, wch, 0.28, [{"t": lab, "size": 8.4, "color": tc, "bold": True,
                                               "align": "center"}], anchor="middle",
                   check=False)
            cx += wch + 0.10
    # supporting mechanisms
    sy2 = fy + 2.60
    supp = [
        ("clock", "Temporary bed holds",
         "Holds and reservations expire after five minutes, evaluated on server reads and "
         "actions. Occupied beds never expire."),
        ("refresh", "Priority-aware reclamation",
         "A higher verified priority can reclaim a lower-priority temporary hold; confirmed "
         "reservations and occupied beds stay protected."),
        ("users", "Controlled states & roles",
         "Temporary Hold, Reserved and Occupied are distinct states; patients, operators and "
         "admins act only within their permissions."),
    ]
    for i, (ic, t, body) in enumerate(supp):
        x = M + i * (4.013 + 0.10)
        d.rrect(x, sy2, 4.013, 1.06, fill=PURPLE, rad=0.09)
        d.icon(ic, x + 0.34, sy2 + 0.34, 0.26, YELLOW)
        d.text(x + 0.62, sy2 + 0.14, 3.25, 0.28, [{"t": t, "size": 10.8, "color": WHITE,
                                                   "bold": True}], name=f"s4s{i}")
        d.text(x + 0.62, sy2 + 0.44, 3.25, 0.56, [{"t": body, "size": 8.5, "color": "E9E1F5",
                                                   "line": 1.02}], name=f"s4sb{i}")
    # innovation statement
    by = sy2 + 1.22
    d.rrect(M, by, 12.233, 0.86, fill=ELECTRIC, rad=0.10)
    d.pill(M + 0.28, by + 0.13, 1.62, 0.28, fill=YELLOW)
    d.text(M + 0.28, by + 0.13, 1.62, 0.28, [{"t": "OUR INNOVATION", "size": 8.8, "color": BLACK,
                                              "bold": True, "align": "center"}],
           anchor="middle", check=False)
    d.text(M + 0.28, by + 0.44, 11.7, 0.36,
           [{"t": "Compatible-care matching + operator-verified priority + controlled bed "
                  "allocation in one workflow.",
             "size": 13.5, "color": WHITE, "bold": True}], anchor="middle", name="innov")
    d.footer()
    d.notes(
        "This is the differentiation slide. One: compatibility — General, ICU and Ventilator are "
        "first-class requirements, not an afterthought. Two: verified priority — Critical, Urgent, "
        "Stable/unverified with FIFO for ties, and crucially a self-declared Critical does not "
        "jump the queue; an operator must verify it. Three: protected reservations — five-minute "
        "expiry on temporary holds, while confirmed reservations and occupied beds cannot be "
        "reclaimed. Underneath: reclamation lets a higher verified priority take a lower-priority "
        "hold, and everything is state- and role-controlled. We are not claiming to invent bed "
        "management or clinical validation — the innovation is the combination, working together.")


# =====================================================================  5
def slide5():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=WHITE)
    d.rect(0, 0, SW, 0.16, fill=ELECTRIC)
    top = d.header("04  ·  TECHNOLOGY & ARCHITECTURE", ELECTRIC, ELECTRIC,
                   "How We Built CareRoute",
                   "Laravel 8 + PHP over MySQL/MariaDB, with emergency state kept in file-locked JSON.")
    lx, lw = M, 4.55
    rx, rw = 5.45, 2.45
    # frontend
    d.rrect(lx, top + 0.04, lw, 0.98, fill=ORANGE, rad=0.09)
    d.icon("grid", lx + 0.32, top + 0.36, 0.26, BLACK)
    d.text(lx + 0.62, top + 0.12, lw - 0.8, 0.28, [{"t": "FRONTEND — role dashboards",
                                                    "size": 11, "color": BLACK, "bold": True}])
    d.text(lx + 0.62, top + 0.42, lw - 0.8, 0.52,
           [{"t": "Laravel Blade views · Bootstrap · custom dashboard styles · JavaScript with "
                  "browser polling", "size": 8.8, "color": BLACK, "line": 1.02}], name="fe")
    d.varrow(lx + lw / 2 - 0.08, top + 1.04, 0.26, ELECTRIC, th=0.16)
    # laravel
    byy = top + 1.32
    d.rrect(lx, byy, lw, 0.98, fill=ELECTRIC, rad=0.09)
    d.icon("gear", lx + 0.32, byy + 0.32, 0.26, YELLOW)
    d.text(lx + 0.62, byy + 0.10, lw - 0.8, 0.28, [{"t": "LARAVEL 8 BACKEND — PHP",
                                                    "size": 11, "color": WHITE, "bold": True}])
    d.text(lx + 0.62, byy + 0.40, lw - 0.8, 0.52,
           [{"t": "Application routes, permissions, session authentication and a Sanctum-"
                  "protected API user route", "size": 8.8, "color": "DCE3FA", "line": 1.02}],
           name="be")
    d.varrow(lx + lw / 2 - 0.08, byy + 1.00, 0.26, PURPLE, th=0.16)
    # emergency service
    cy = byy + 1.28
    d.rrect(lx, cy, lw, 1.42, fill=PURPLE, rad=0.09)
    d.icon("bolt", lx + 0.32, cy + 0.32, 0.26, YELLOW)
    d.text(lx + 0.62, cy + 0.10, lw - 0.8, 0.28, [{"t": "EMERGENCY SERVICE", "size": 11,
                                                   "color": WHITE, "bold": True}])
    d.text(lx + 0.62, cy + 0.40, lw - 0.8, 0.92,
           [{"t": "Matching · verified priority · temporary holds · reservations · five-minute "
                  "expiry · file-locked updates", "size": 8.8, "color": "E9E1F5", "line": 1.05}],
           name="svc")
    # json state (right, aligned with service)
    d.rrect(rx, cy, rw, 1.42, fill=PURPLE_TINT, line=PURPLE, lw=1.4, rad=0.09)
    d.icon("doc", rx + 0.32, cy + 0.32, 0.26, PURPLE)
    d.text(rx + 0.60, cy + 0.12, rw - 0.75, 0.50, [{"t": "JSON EMERGENCY STATE", "size": 10,
                                                    "color": PURPLE, "bold": True,
                                                    "line": 1.0}])
    d.text(rx + 0.22, cy + 0.66, rw - 0.42, 0.66,
           [{"t": "Separate demo-state file, serialized with file locking", "size": 8.6,
             "color": INK_SOFT, "line": 1.04}], name="json")
    d.shape(MSO_SHAPE.LEFT_RIGHT_ARROW, lx + lw + 0.04, cy + 0.62, rx - lx - lw - 0.08, 0.18,
            fill=PURPLE)
    # mysql (right, aligned with laravel)
    d.rrect(rx, byy, rw, 0.98, fill=MINT, rad=0.09)
    d.icon("db", rx + 0.32, byy + 0.32, 0.26, BLACK)
    d.text(rx + 0.60, byy + 0.10, rw - 0.75, 0.28, [{"t": "MYSQL / MARIADB", "size": 10,
                                                     "color": BLACK, "bold": True}])
    d.text(rx + 0.60, byy + 0.40, rw - 0.75, 0.52,
           [{"t": "Accounts · roles · modules · legacy management records", "size": 8.6,
             "color": BLACK, "line": 1.02}], name="mysql")
    d.shape(MSO_SHAPE.LEFT_RIGHT_ARROW, lx + lw + 0.04, byy + 0.40, rx - lx - lw - 0.08, 0.18,
            fill=MINT)
    # note band
    ny = cy + 1.58
    d.rrect(M, ny, 7.35, 0.72, fill=YELLOW_TINT, line=YELLOW, lw=1.2, rad=0.12)
    d.icon("alert", M + 0.30, ny + 0.36, 0.22, BLACK)
    d.text(M + 0.52, ny + 0.08, 6.6, 0.58,
           [{"t": "Emergency demo state lives in JSON with file locking — MySQL holds accounts, "
                  "roles, modules and legacy hospital-management records.",
             "size": 9.2, "color": BLACK, "bold": True, "line": 1.04}], anchor="middle",
           name="note5")
    # stack panel (right column)
    px, pw = 8.15, 4.63
    d.rrect(px, top + 0.04, pw, 4.66, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.05)
    d.text(px + 0.24, top + 0.20, pw - 0.5, 0.30, [{"t": "TECHNOLOGY STACK", "size": 12,
                                                    "color": ELECTRIC, "bold": True}])
    rows = [("BACKEND", ELECTRIC, WHITE, "Laravel 8 · PHP"),
            ("DATABASE", MINT, BLACK, "MySQL / MariaDB"),
            ("EMERGENCY STATE", PURPLE, WHITE, "JSON state · file locking"),
            ("FRONTEND", ORANGE, BLACK, "Blade · Bootstrap · custom styles · JS polling"),
            ("AUTH", MAGENTA, WHITE, "Laravel UI sessions · Sanctum API route"),
            ("BUILD TOOLS", YELLOW, BLACK, "Composer · Laravel Mix 6 · Sass · Axios")]
    ry = top + 0.58
    for tag, bg, tc, val in rows:
        d.pill(px + 0.24, ry, 1.62, 0.30, fill=bg)
        d.text(px + 0.24, ry, 1.62, 0.30, [{"t": tag, "size": 8.0, "color": tc, "bold": True,
                                            "align": "center"}], anchor="middle", check=False)
        d.text(px + 2.00, ry, pw - 2.2, 0.44, [{"t": val, "size": 9.2, "color": BLACK,
                                                "line": 1.02}], name=f"row:{tag}")
        ry += 0.60
    d.rrect(px + 0.24, ry + 0.04, pw - 0.48, 0.44, fill=BLUE_TINT, rad=0.14)
    d.text(px + 0.42, ry + 0.08, pw - 0.8, 0.36,
           [{"t": "Five demo hospitals with predefined distances seed the prototype.",
             "size": 8.8, "color": ELECTRIC, "bold": True, "line": 1.04}], anchor="middle",
           name="seed5")
    d.footer()
    d.notes(
        "Keep this honest and concrete. Backend is Laravel 8 on PHP. MySQL/MariaDB stores accounts, "
        "roles, modules and legacy hospital-management records — but the emergency demo state is "
        "deliberately separate: a JSON state file protected by file locking so concurrent updates "
        "are serialized. The frontend is server-rendered Laravel Blade with Bootstrap, custom "
        "dashboard styles and JavaScript browser polling. Auth is Laravel UI session auth plus a "
        "Sanctum-protected API user route. Tooling: Composer, Laravel Mix 6, Sass and Axios. Point "
        "at the arrows: dashboards talk to Laravel; the emergency service owns matching, priority, "
        "holds, reservations and expiry; MySQL is not the emergency state store.")


# =====================================================================  6
def slide6():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=WHITE)
    d.rect(0, 0, SW, 0.16, fill=MAGENTA)
    top = d.header("05  ·  LIVE DEMO WORKFLOW", MAGENTA, MAGENTA,
                   "From Emergency Request to Occupied Bed",
                   "The documented six-step demonstration, run on seeded demo data.")
    steps = [
        ("refresh", PURPLE, "Admin reset", "Administrator resets the emergency demo state."),
        ("alert", MAGENTA, "First emergency", "Critical / ICU request from an accident location; "
                                              "patient requests Hospital C."),
        ("shieldcheck", ORANGE, "Verify & reserve", "Hospital C verifies severity and accepts the "
                                                    "request → Reserved."),
        ("alert", MAGENTA, "Second emergency", "Second ICU request; Hospital C's reservation is "
                                               "protected, so Hospital B is recommended."),
        ("shieldcheck", ORANGE, "Second reservation", "Hospital B verifies and accepts the second "
                                                      "request."),
        ("check", MINT, "Arrival confirmed", "Hospital C marks the first patient arrived → bed "
                                             "state becomes Occupied."),
    ]
    sw, sh_, gap = 1.90, 1.72, 0.147
    x0 = M + (12.233 - (6 * sw + 5 * gap)) / 2
    sy = top + 0.04
    for i, (ic, col, t, body) in enumerate(steps):
        x = x0 + i * (sw + gap)
        d.rrect(x, sy, sw, sh_, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.08)
        d.shape(MSO_SHAPE.ROUND_2_SAME_RECTANGLE, x, sy, sw, 0.10, fill=col, rad=0.5)
        d.oval(x + 0.14, sy + 0.24, 0.42, 0.42, fill=col)
        d.icon(ic, x + 0.35, sy + 0.45, 0.24, WHITE if col != YELLOW else BLACK)
        d.text(x + 0.64, sy + 0.24, sw - 0.74, 0.42, [{"t": f"STEP {i+1}", "size": 8.4,
                                                       "color": INK_SOFT, "bold": True}],
               anchor="middle", check=False)
        d.text(x + 0.14, sy + 0.76, sw - 0.26, 0.30, [{"t": t, "size": 10.6, "color": BLACK,
                                                       "bold": True}], name=f"s6t{i}")
        d.text(x + 0.14, sy + 1.06, sw - 0.26, 0.64, [{"t": body, "size": 8.4,
                                                       "color": INK_SOFT, "line": 1.02}],
               name=f"s6b{i}")
        if i < 5:
            d.harrow(x + sw + 0.012, sy + sh_ / 2 - 0.075, gap - 0.024, GREY_LINE, th=0.15)
    # state transition strip
    ty = sy + sh_ + 0.16
    d.text(M, ty, 1.2, 0.34, [{"t": "BED STATES", "size": 9.4, "color": ELECTRIC, "bold": True}],
           anchor="middle", check=False)
    chain = [("Temporary Hold", ORANGE_TINT, ORANGE, ORANGE), ("Reserved", ORANGE, ORANGE, BLACK),
             ("Occupied", MINT, MINT, BLACK)]
    cx = M + 1.25
    for i, (lab, bg, ln, tc) in enumerate(chain):
        w = 1.55
        d.pill(cx, ty, w, 0.34, fill=bg, line=ln, lw=1.2)
        d.text(cx, ty, w, 0.34, [{"t": lab, "size": 9.4, "color": tc, "bold": True,
                                  "align": "center"}], anchor="middle", check=False)
        if i < 2:
            d.harrow(cx + w + 0.05, ty + 0.09, 0.26, ELECTRIC, th=0.16)
        cx += w + 0.36
    d.text(cx + 0.05, ty, 1.5, 0.34, [{"t": "also possible:", "size": 8.6, "color": INK_SOFT,
                                       "italic": True}], anchor="middle", check=False)
    d.pill(cx + 1.05, ty, 1.05, 0.34, fill=WHITE, line=MAGENTA, lw=1.2)
    d.text(cx + 1.05, ty, 1.05, 0.34, [{"t": "Rejected", "size": 9.0, "color": MAGENTA,
                                        "bold": True, "align": "center"}], anchor="middle",
           check=False)
    d.pill(cx + 2.20, ty, 1.62, 0.34, fill=WHITE, line=PURPLE, lw=1.2)
    d.text(cx + 2.20, ty, 1.62, 0.34, [{"t": "Expired (5 min)", "size": 9.0, "color": PURPLE,
                                        "bold": True, "align": "center"}], anchor="middle",
           check=False)
    # mock window + demo scope
    my = ty + 0.52
    d.rrect(M, my, 7.35, 2.30, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.05)
    d.shape(MSO_SHAPE.ROUND_2_SAME_RECTANGLE, M, my, 7.35, 0.34, fill=BLACK, rad=0.16)
    for i, c in enumerate([MAGENTA, YELLOW, MINT]):
        d.oval(M + 0.16 + i * 0.18, my + 0.11, 0.12, 0.12, fill=c)
    d.text(M + 0.78, my, 5.4, 0.34, [{"t": "CareRoute — operator dashboard  (illustrative mock)",
                                      "size": 8.6, "color": WHITE, "bold": True}],
           anchor="middle", check=False)
    d.pill(M + 6.05, my + 0.06, 1.18, 0.22, fill=MAGENTA)
    d.text(M + 6.05, my + 0.06, 1.18, 0.22, [{"t": "LIVE POLL 5s", "size": 7.4, "color": WHITE,
                                              "bold": True, "align": "center"}],
           anchor="middle", check=False)
    hosp = [("Hospital A", [("ICU", MINT), ("GEN", MINT)]),
            ("Hospital B", [("ICU", ORANGE), ("GEN", MINT)]),
            ("Hospital C", [("ICU", MAGENTA), ("VENT", MINT)]),
            ("Hospital D", [("ICU", MINT), ("GEN", ORANGE)]),
            ("Hospital E", [("ICU", MINT), ("GEN", MINT)])]
    hy = my + 0.44
    for name, tags in hosp:
        d.text(M + 0.20, hy, 1.35, 0.26, [{"t": name, "size": 8.8, "color": BLACK, "bold": True}],
               anchor="middle", check=False)
        tx = M + 1.60
        for lab, col in tags:
            d.pill(tx, hy + 0.015, 0.72, 0.22, fill=col)
            d.text(tx, hy + 0.015, 0.72, 0.22, [{"t": lab, "size": 7.2, "color": BLACK,
                                                 "bold": True, "align": "center"}],
                   anchor="middle", check=False)
            tx += 0.80
        hy += 0.285
    d.text(M + 0.20, hy + 0.02, 4.4, 0.24,
           [{"t": "bed-state chips: hold · reserved · occupied", "size": 7.6, "color": INK_SOFT,
             "italic": True}], check=False)
    # request card inside mock
    qx = M + 4.35
    d.rrect(qx, my + 0.46, 2.82, 1.62, fill=BLUE_TINT, line=ELECTRIC, lw=1.0, rad=0.08)
    d.pill(qx + 0.14, my + 0.58, 1.30, 0.24, fill=MAGENTA)
    d.text(qx + 0.14, my + 0.58, 1.30, 0.24, [{"t": "CRITICAL · verified", "size": 7.6,
                                               "color": WHITE, "bold": True, "align": "center"}],
           anchor="middle", check=False)
    d.text(qx + 0.14, my + 0.88, 2.55, 0.60,
           [{"t": "REQ-002 · ICU · accident junction · requests nearest compatible hospital",
             "size": 8.2, "color": BLACK, "line": 1.02}], name="reqcard")
    d.pill(qx + 0.14, my + 1.70, 1.24, 0.26, fill=MINT)
    d.text(qx + 0.14, my + 1.70, 1.24, 0.26, [{"t": "Accept → Reserved", "size": 7.8,
                                               "color": BLACK, "bold": True, "align": "center"}],
           anchor="middle", check=False)
    d.pill(qx + 1.46, my + 1.70, 0.86, 0.26, fill=WHITE, line=MAGENTA, lw=1.0)
    d.text(qx + 1.46, my + 1.70, 0.86, 0.26, [{"t": "Reject", "size": 7.8, "color": MAGENTA,
                                               "bold": True, "align": "center"}],
           anchor="middle", check=False)
    # demo scope panel
    d.rrect(8.15, my, 4.63, 2.30, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.05)
    d.text(8.39, my + 0.12, 4.2, 0.26, [{"t": "DEMO SCOPE", "size": 10.5, "color": ELECTRIC,
                                         "bold": True}])
    d.text(8.39, my + 0.42, 4.2, 1.00, bullets(
        ["Five seeded demo hospitals", "Predefined distances between locations",
         "Admin-resettable emergency state", "Protected reservations steer recommendations"],
        ELECTRIC, size=8.8, gap=2), name="scope6")
    d.rrect(8.39, my + 1.66, 4.15, 0.48, fill=MAGENTA_TINT, line=MAGENTA, lw=1.0, rad=0.16)
    d.text(8.55, my + 1.66, 3.85, 0.48,
           [{"t": "Seeded prototype — not a live connection to real hospital capacity.",
             "size": 8.4, "color": MAGENTA, "bold": True, "line": 1.02}], anchor="middle",
           name="scope6warn")
    d.footer()
    d.notes(
        "Tell the demo as a story in six beats. Admin resets the seeded state. A patient submits a "
        "Critical ICU request from an accident location and asks for Hospital C; Hospital C verifies "
        "severity and accepts — Reserved. A second ICU request then arrives: because Hospital C's "
        "confirmed reservation is protected, the recommendation engine points to Hospital B, which "
        "verifies and accepts. Finally Hospital C marks the first patient arrived and the bed flips "
        "to Occupied. Show the state chain Hold → Reserved → Occupied, plus rejection and five-minute "
        "expiry as real outcomes. The mock is illustrative; the data is seeded — say so plainly.")


# =====================================================================  7
def slide7():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=WHITE)
    d.rect(0, 0, SW, 0.16, fill=PURPLE)
    top = d.header("06  ·  SECURITY, ACCESS CONTROL & RELIABILITY", PURPLE, PURPLE,
                   "Controlled Access. Structured Decisions.",
                   "Protections and coordination mechanisms present in the prototype today.")
    roles = [
        ("person", ELECTRIC, WHITE, "Patient",
         ["Submit & track own emergency requests", "Patient ownership checks enforced"],
         "Cannot act on other patients' requests"),
        ("shieldcheck", ORANGE, BLACK, "Hospital Operator",
         ["Review, verify severity, accept / reject", "Manage reservation & arrival states"],
         "Scoped to the assigned hospital only"),
        ("gear", PURPLE, WHITE, "Administrator",
         ["View emergency records", "Reset demo emergency data"],
         "Emergency reset is admin-only"),
    ]
    ry = top + 0.06
    for i, (ic, col, tc, t, items, limit) in enumerate(roles):
        x = M + i * (4.013 + 0.10)
        d.rrect(x, ry, 4.013, 2.16, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.06)
        d.shape(MSO_SHAPE.ROUND_2_SAME_RECTANGLE, x, ry, 4.013, 0.50, fill=col, rad=0.15)
        d.icon(ic, x + 0.34, ry + 0.25, 0.26, tc)
        d.text(x + 0.60, ry, 3.3, 0.50, [{"t": t, "size": 12.5, "color": tc, "bold": True}],
               anchor="middle", check=False)
        yy = ry + 0.66
        for it in items:
            d.oval(x + 0.24, yy + 0.03, 0.20, 0.20, fill=MINT)
            d.icon("check", x + 0.34, yy + 0.13, 0.13, WHITE)
            d.text(x + 0.52, yy, 3.3, 0.28, [{"t": it, "size": 9.4, "color": BLACK}],
                   anchor="middle", name=f"r{i}:{it[:20]}")
            yy += 0.34
        d.oval(x + 0.24, yy + 0.05, 0.20, 0.20, fill=MAGENTA_TINT, line=MAGENTA, lw=1.0)
        d.icon("lock", x + 0.34, yy + 0.15, 0.12, MAGENTA)
        d.text(x + 0.52, yy + 0.02, 3.3, 0.28, [{"t": limit, "size": 9.2, "color": MAGENTA,
                                                 "bold": True}], anchor="middle",
               name=f"rl{i}")
    # permission boundary
    byy = ry + 2.30
    d.line(M, byy + 0.17, 12.233, 0, PURPLE, lw=1.6, dash=DASH.DASH)
    d.pill(3.30, byy, 6.73, 0.36, fill=PURPLE)
    d.icon("lock", 3.56, byy + 0.18, 0.18, YELLOW)
    d.text(3.78, byy, 6.1, 0.36,
           [{"t": "PERMISSION BOUNDARY — every role sees and does only what it is allowed",
             "size": 9.4, "color": WHITE, "bold": True}], anchor="middle", check=False)
    # checklist + limitations
    cy = byy + 0.52
    d.rrect(M, cy, 7.35, 1.62, fill=WHITE, line=GREY_LINE, lw=1.0, rad=0.05)
    d.text(M + 0.24, cy + 0.12, 6.8, 0.26, [{"t": "SECURITY & RELIABILITY CHECKLIST",
                                             "size": 10.5, "color": ELECTRIC, "bold": True}])
    left = ["Session authentication", "CSRF protection on emergency actions",
            "Patient ownership checks", "Hospital-scoped operator actions"]
    right = ["Admin-only emergency reset", "Decision history for emergency actions",
             "File locking serializes JSON updates", "Dashboards poll every 5 seconds"]
    checkrow(M + 0.24, cy + 0.46, 3.4, left, size=9.0, row_h=0.28)
    checkrow(M + 3.80, cy + 0.46, 3.4, right, size=9.0, row_h=0.28)
    d.rrect(8.15, cy, 4.63, 1.62, fill=ORANGE, rad=0.06)
    d.text(8.39, cy + 0.12, 4.2, 0.26, [{"t": "PROTOTYPE LIMITATIONS — STATED PLAINLY",
                                         "size": 10, "color": BLACK, "bold": True}])
    d.text(8.39, cy + 0.44, 4.15, 1.06,
           [{"t": "Validation, authorization, legacy endpoints, uploads, password-reset workflows "
                  "and production security require additional review. The README does not establish "
                  "that the application is production-ready.",
             "size": 9.0, "color": BLACK, "line": 1.05}], name="limits7")
    # why band
    wy = cy + 1.76
    d.rrect(M, wy, 12.233, 0.56, fill=ELECTRIC, rad=0.12)
    d.text(M + 0.28, wy, 11.7, 0.56,
           [{"t": "Why it matters:  users reach only their permitted requests  ·  operators manage "
                  "only their assigned scope  ·  emergency actions flow through controlled routes  "
                  "·  concurrent updates are coordinated.",
             "size": 9.6, "color": WHITE, "bold": True, "line": 1.02}], anchor="middle",
           name="why7")
    d.footer()
    d.notes(
        "Trust slide. Three role cards show the permission boundary: patients are limited by "
        "ownership checks to their own requests; operators are scoped to their assigned hospital; "
        "the emergency reset is admin-only. The checklist is what exists today: session auth, CSRF "
        "protection on emergency actions, ownership checks, hospital scoping, admin-only reset, "
        "decision history, file locking that serializes concurrent JSON updates, and five-second "
        "dashboard polling for fresh state. Then be candid: this is a prototype — validation, "
        "authorization, legacy endpoints, uploads, password resets and production security still "
        "need review. We do not claim penetration testing or regulatory compliance.")


# =====================================================================  8
def slide8():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=ELECTRIC)
    d.oval(10.9, -1.4, 3.4, 3.4, fill=None, line=PURPLE, lw=2.2)
    d.oval(-0.9, 5.6, 2.4, 2.4, fill=None, line=PURPLE, lw=2.0)
    top = d.header("07  ·  BUSINESS MODEL & MARKET OPPORTUNITY", YELLOW, YELLOW,
                   "Turning CareRoute into a Healthcare Coordination Platform",
                   "A proposed business model for the platform — not an existing revenue stream.",
                   dark=True, title_size=24)
    # flow
    fy = top + 0.04
    blocks = [(WHITE, ELECTRIC, "Hospitals, groups & networks",
               "private · multi-hospital · healthcare networks · emergency coordination orgs"),
              (ORANGE, BLACK, "CareRoute platform",
               "coordination layer: matching, verified priority, reservations"),
              (MINT, BLACK, "Coordinated emergency workflow",
               "structured requests · visible status · protected allocations")]
    bw, gap = 3.62, 0.60
    x0 = M + (12.233 - (3 * bw + 2 * gap)) / 2
    for i, (bg, tc, t, sub) in enumerate(blocks):
        x = x0 + i * (bw + gap)
        d.rrect(x, fy, bw, 0.92, fill=bg, rad=0.10)
        d.text(x + 0.20, fy + 0.10, bw - 0.4, 0.30, [{"t": t, "size": 11.5, "color": tc,
                                                      "bold": True}], name=f"s8f{i}")
        d.text(x + 0.20, fy + 0.42, bw - 0.4, 0.44, [{"t": sub, "size": 8.4, "color": tc,
                                                      "line": 1.02}], name=f"s8fs{i}")
        if i < 2:
            d.harrow(x + bw + 0.08, fy + 0.38, gap - 0.16, ORANGE, th=0.18)
    # revenue label + cards
    d.pill(M, fy + 1.10, 3.30, 0.30, fill=YELLOW)
    d.text(M, fy + 1.10, 3.30, 0.30, [{"t": "POTENTIAL REVENUE STREAMS  (PROPOSED)", "size": 8.8,
                                       "color": BLACK, "bold": True, "align": "center"}],
           anchor="middle", check=False)
    ry = fy + 1.50
    rev = [("1", "SaaS subscription", "Monthly or annual subscriptions for participating "
                                      "hospitals."),
           ("2", "Enterprise plans", "Priced by facilities, user accounts, operational needs and "
                                      "support."),
           ("3", "Setup & integration", "Onboarding, configuration, training and approved "
                                         "integrations."),
           ("4", "Reporting & analytics", "Optional operational reporting and capacity-visibility "
                                           "services.")]
    for i, (n, t, body) in enumerate(rev):
        x = M + i * (2.983 + 0.10)
        d.rrect(x, ry, 2.983, 1.16, fill=ORANGE, rad=0.09)
        d.oval(x + 0.16, ry + 0.16, 0.34, 0.34, fill=BLACK)
        d.text(x + 0.16, ry + 0.16, 0.34, 0.34, [{"t": n, "size": 12, "color": YELLOW,
                                                  "bold": True, "align": "center"}],
               anchor="middle", check=False)
        d.text(x + 0.60, ry + 0.16, 2.25, 0.30, [{"t": t, "size": 11, "color": BLACK,
                                                  "bold": True}], anchor="middle",
               name=f"s8r{i}")
        d.text(x + 0.18, ry + 0.56, 2.65, 0.54, [{"t": body, "size": 8.6, "color": BLACK,
                                                  "line": 1.02}], name=f"s8rb{i}")
    # bottom panels
    byy = ry + 1.34
    d.rrect(M, byy, 6.00, 1.90, fill=MINT, rad=0.07)
    d.text(M + 0.24, byy + 0.12, 5.5, 0.26, [{"t": "VALUE PROPOSITION", "size": 10.5,
                                              "color": BLACK, "bold": True}])
    checkrow(M + 0.24, byy + 0.44, 5.55,
             ["Structured emergency request handling", "More visible reservation status",
              "Better coordination across participating facilities",
              "Potential reduction in manual coordination effort*",
              "Foundation for integration with verified hospital systems"],
             size=8.8, tcolor=BLACK, row_h=0.27, circle=BLACK)
    d.rrect(6.78, byy, 5.99, 0.88, fill=PURPLE, rad=0.09)
    d.text(6.98, byy + 0.08, 5.6, 0.24, [{"t": "TARGET CUSTOMERS", "size": 9.6, "color": YELLOW,
                                          "bold": True}])
    d.text(6.98, byy + 0.34, 5.6, 0.50,
           [{"t": "Private hospitals · multi-hospital groups · healthcare networks · emergency "
                  "coordination organisations · public-sector programs**",
             "size": 8.6, "color": WHITE, "line": 1.04}], name="cust8")
    d.rrect(6.78, byy + 0.96, 5.99, 0.94, fill=WHITE, rad=0.09)
    d.text(6.98, byy + 1.06, 5.6, 0.24, [{"t": "GROWTH PATH — PILOT FIRST", "size": 9.6,
                                          "color": ELECTRIC, "bold": True}])
    d.text(6.98, byy + 1.32, 5.6, 0.52,
           [{"t": "Controlled pilot → measure processing time, recommendation accuracy, reservation "
                  "conflicts, operator workload & adoption → then expand.",
             "size": 8.6, "color": INK_SOFT, "line": 1.04}], name="growth8")
    d.text(M, 6.74, 12.233, 0.24,
           [{"t": "*Subject to validation.   **Public-sector participation subject to authorization "
                  "and procurement requirements. No market size, customers or revenue are claimed.",
             "size": 7.8, "color": "C9D2F7", "italic": True}], check=False)
    d.footer(dark=True)
    d.notes(
        "Be explicit that this is a proposed model, not revenue we have. Customers: private "
        "hospitals, multi-hospital groups, healthcare networks, emergency coordination "
        "organisations, and public-sector programs where authorization and procurement allow. Four "
        "potential streams: SaaS subscriptions, enterprise plans priced by facilities and users, "
        "setup and integration fees, and optional reporting and analytics. The value proposition is "
        "operational: structured requests, visible reservation status, better cross-facility "
        "coordination and less manual effort — subject to validation. Growth plan is deliberately "
        "conservative: pilot first, measure processing time, recommendation accuracy, conflicts, "
        "workload and adoption, then expand. No invented market sizes or traction.")


# =====================================================================  9
def slide9():
    d.new_slide()
    d.rect(0, 0, SW, SH, fill=WHITE)
    d.rect(0, 0, SW, 0.16, fill=ORANGE)
    top = d.header("08  ·  FUTURE SCOPE & DEVELOPMENT ROADMAP", ORANGE, ORANGE,
                   "From Prototype to Real-World Healthcare Coordination",
                   "Three phases — each clearly separated from what exists today.",
                   title_size=26)
    phases = [
        (ELECTRIC, BLUE_TINT, "PHASE 1", "Strengthen the prototype",
         ["Improve validation & automated tests", "Review authorization & security",
          "Replace fragile demo-state assumptions with robust persistence",
          "Improve auditability & operational error handling"]),
        (PURPLE, PURPLE_TINT, "PHASE 2", "Connect real healthcare systems",
         ["Integrate verified hospital bed availability", "Add accurate location & routing services",
          "Real-time updates via a push-based architecture", "Add reliable notifications",
          "Data-sharing agreements & access controls"]),
        (ORANGE, ORANGE_TINT, "PHASE 3", "Intelligent coordination",
         ["Explore demand forecasting", "Investigate discharge prediction",
          "Evaluate optimization algorithms for matching",
          "Develop authorized reporting integrations",
          "Pilot with participating hospitals & measure outcomes"]),
    ]
    py = top + 0.06
    for i, (col, tint, ph, t, items) in enumerate(phases):
        x = M + i * (4.013 + 0.10)
        d.rrect(x, py, 4.013, 2.66, fill=tint, line=col, lw=1.4, rad=0.06)
        d.pill(x + 0.22, py + 0.18, 0.92, 0.28, fill=YELLOW)
        d.text(x + 0.22, py + 0.18, 0.92, 0.28, [{"t": ph, "size": 8.6, "color": BLACK,
                                                  "bold": True, "align": "center"}],
               anchor="middle", check=False)
        d.text(x + 0.24, py + 0.54, 3.55, 0.30, [{"t": t, "size": 11.5, "color": col,
                                                 "bold": True}], name=f"s9t{i}")
        d.text(x + 0.24, py + 0.90, 3.55, 1.66, bullets(items, col, size=9.2, gap=4),
               name=f"s9b{i}")
        if i < 2:
            d.harrow(x + 4.013 + 0.012, py + 1.25, 0.076, col, th=0.16)
    # current vs future
    cy = py + 2.84
    d.rrect(M, cy, 6.00, 1.86, fill=MINT_TINT, line=MINT, lw=1.4, rad=0.06)
    d.text(M + 0.24, cy + 0.14, 5.5, 0.26, [{"t": "CURRENT PROTOTYPE — TODAY", "size": 10.5,
                                             "color": BLACK, "bold": True}])
    cur = ["Seeded hospital data", "Five demo hospitals", "Fixed distances",
           "JSON emergency state", "Browser polling", "Rule-based matching & priority"]
    cx, cyy = M + 0.24, cy + 0.50
    for lab in cur:
        w = 0.30 + len(lab) * 0.062
        if cx + w > M + 5.85:
            cx = M + 0.24
            cyy += 0.36
        d.pill(cx, cyy, w, 0.28, fill=MINT)
        d.text(cx, cyy, w, 0.28, [{"t": lab, "size": 8.2, "color": BLACK, "bold": True,
                                   "align": "center"}], anchor="middle", check=False)
        cx += w + 0.12
    d.rrect(6.78, cy, 5.99, 1.86, fill=YELLOW_TINT, line=YELLOW, lw=1.4, rad=0.06)
    d.text(7.02, cy + 0.14, 3.6, 0.26, [{"t": "FUTURE ENHANCEMENTS", "size": 10.5,
                                         "color": BLACK, "bold": True}])
    d.pill(10.55, cy + 0.12, 2.05, 0.28, fill=MAGENTA)
    d.text(10.55, cy + 0.12, 2.05, 0.28, [{"t": "PLANNED — NOT IMPLEMENTED", "size": 8.0,
                                           "color": WHITE, "bold": True, "align": "center"}],
           anchor="middle", check=False)
    fut = ["Live hospital integrations", "GPS-based routing", "Real-time push updates",
           "Machine-learning predictions", "Authorized government reporting"]
    cx, cyy = 7.02, cy + 0.50
    for lab in fut:
        w = 0.30 + len(lab) * 0.062
        if cx + w > 6.78 + 5.75:
            cx = 7.02
            cyy += 0.36
        d.pill(cx, cyy, w, 0.28, fill=YELLOW)
        d.text(cx, cyy, w, 0.28, [{"t": lab, "size": 8.2, "color": BLACK, "bold": True,
                                   "align": "center"}], anchor="middle", check=False)
        cx += w + 0.12
    d.text(7.02, cy + 1.52, 5.6, 0.26,
           [{"t": "Every future item is a proposal — nothing above the line is claimed as built.",
             "size": 8.4, "color": INK_SOFT, "italic": True}], check=False)
    d.footer()
    d.notes(
        "Roadmap with honest phase gates. Phase 1 hardens what we have: validation, automated "
        "tests, authorization and security review, replacing fragile demo-state assumptions with "
        "robust persistence, better auditability and error handling. Phase 2 connects reality: "
        "verified hospital bed availability, accurate location and routing, push-based real-time "
        "updates, reliable notifications, and the data-sharing agreements and access controls that "
        "must come first. Phase 3 explores intelligence: demand forecasting, discharge prediction, "
        "optimization for matching, authorized reporting, and measured pilots. The bottom panels "
        "keep judges honest with us: left is exactly what exists today; right is planned only.")


# =====================================================================  10
def slide10():
    d.new_slide()
    d.picture(os.path.join(ASSETS, "closing_norm.png"), 0, 0, SW, SH)
    ov = d.rect(0, 0, 8.35, SH, fill=ELECTRIC)
    translucent(ov, 12)
    ov2 = d.rect(8.35, 0, SW - 8.35, SH, fill=ELECTRIC)
    translucent(ov2, 42)
    d.rect(8.30, 0, 0.06, SH, fill=ORANGE)
    # header
    d.pill(M, 0.46, 1.58, 0.32, fill=YELLOW)
    d.text(M, 0.46, 1.58, 0.32, [{"t": "TEAM TECH HEAD", "size": 9.0, "color": BLACK, "bold": True,
                                  "align": "center"}], anchor="middle", check=False)
    d.text(2.26, 0.46, 5.6, 0.32, [{"t": "CAREROUTE  ·  HACKATHON PRESENTATION", "size": 8.8,
                                    "color": "C9D2F7", "bold": True}], anchor="middle",
           check=False)
    d.text(M, 0.94, 7.4, 1.06, [{"t": "Better Coordination for Emergency Care", "size": 31,
                                 "color": WHITE, "bold": True, "line": 1.0}], name="t10")
    d.rect(M + 0.02, 2.02, 1.3, 0.07, fill=MAGENTA)
    # recap grid
    rec = [(MAGENTA, "THE PROBLEM", "Emergency bed coordination is hard when availability, care "
                                    "needs and priority lack a structured workflow."),
           (ORANGE, "OUR SOLUTION", "Coordinated requests, compatible hospital recommendations, "
                                     "operator verification, tracked bed-allocation states."),
           (YELLOW, "OUR INNOVATION", "Compatibility matching · verified priority · temporary "
                                       "holds · protected reservations · role-based actions."),
           (PURPLE, "TECHNICAL FOUNDATION", "Laravel · PHP · MySQL/MariaDB · JSON emergency "
                                             "state · role-based dashboards."),
           (MINT, "BUSINESS OPPORTUNITY", "A hospital-facing SaaS & integration platform — "
                                           "proposed, subject to validation and adoption."),
           (WHITE, "OUR VISION", "Verified, timely information helps providers coordinate "
                                 "emergency capacity more effectively.")]
    gx0, gy0, gw, gh = M, 2.20, 3.72, 0.74
    for i, (col, lab, body) in enumerate(rec):
        x = gx0 + (i % 2) * (gw + 0.16)
        y = gy0 + (i // 2) * (gh + 0.05)
        d.rect(x, y, 0.055, gh - 0.06, fill=col)
        d.text(x + 0.16, y, gw - 0.2, 0.22, [{"t": lab, "size": 8.4, "color": col, "bold": True}])
        d.text(x + 0.16, y + 0.22, gw - 0.2, 0.50, [{"t": body, "size": 8.4, "color": "E8ECFB",
                                                     "line": 1.03}], name=f"rec{i}")
    # closing statement
    d.rrect(M, 4.66, 7.60, 0.78, fill=ORANGE, rad=0.10)
    d.text(M + 0.24, 4.66, 7.12, 0.78,
           [{"t": "“CareRoute — helping the right emergency request reach the right "
                  "available care facility through smarter coordination.”",
             "size": 11.2, "color": BLACK, "bold": True, "line": 1.05}], anchor="middle",
           name="close10")
    # team
    d.text(M, 5.56, 3.0, 0.26, [{"t": "TEAM TECH HEAD", "size": 9.4, "color": YELLOW,
                                 "bold": True}], check=False)
    team = [("TJ", "Tanay Jorihar", ORANGE, BLACK), ("PV", "Puneet K. Verma", MAGENTA, WHITE),
            ("SS", "Shraddha Shetty", MINT, BLACK), ("LB", "Lalit Bist", YELLOW, BLACK)]
    tx = M
    for ini, name, bg, tc in team:
        d.oval(tx, 5.86, 0.40, 0.40, fill=bg)
        d.text(tx, 5.86, 0.40, 0.40, [{"t": ini, "size": 10.5, "color": tc, "bold": True,
                                       "align": "center"}], anchor="middle", check=False)
        d.text(tx + 0.48, 5.86, 1.42, 0.40, [{"t": name, "size": 9.4, "color": WHITE,
                                              "bold": True}], anchor="middle", check=False)
        tx += 1.92
    # thank you
    d.text(M, 6.38, 4.6, 0.62, [{"t": "Thank You", "size": 30, "color": WHITE, "bold": True}],
           name="ty")
    d.pill(4.35, 6.50, 1.62, 0.40, fill=None, line=YELLOW, lw=1.6)
    d.text(4.35, 6.50, 1.62, 0.40, [{"t": "Questions?", "size": 12, "color": YELLOW, "bold": True,
                                     "align": "center"}], anchor="middle", check=False)
    d.footer(dark=True)
    d.notes(
        "Close the loop in twenty seconds. Problem: unstructured emergency bed coordination. "
        "Solution: one workflow from request to arrival. Innovation: compatibility matching, "
        "verified priority, temporary holds and protected reservations with role-based actions. "
        "Foundation: Laravel, PHP, MySQL/MariaDB and a JSON emergency state with role-based "
        "dashboards. Opportunity: a hospital-facing SaaS and integration platform, proposed and "
        "honest about validation. Vision: verified, timely information so providers can coordinate "
        "emergency capacity. Then slow down, name the team — Tanay, Puneet, Shraddha, Lalit — say "
        "the closing line, and invite questions.")


for fn in (slide1, slide2, slide3, slide4, slide5, slide6, slide7, slide8, slide9, slide10):
    fn()

d.save(OUT)
print("saved", OUT)
print("slides:", len(d.prs.slides.__iter__.__self__._sldIdLst))
if d.warnings:
    print("\nWARNINGS:")
    for w in d.warnings:
        print(" -", w)
else:
    print("no overflow warnings")
