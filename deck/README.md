# CareRoute — Hackathon Presentation (Team Tech Head)

10-slide, 16:9 hackathon pitch deck for **CareRoute — Emergency Bed Coordination System**.

- Deliverable: `CareRoute_Hackathon_Deck_TeamTechHead.pptx` (editable PowerPoint, speaker notes on every slide)
- Generator: `build_deck.py` + design system `deckkit.py` (python-pptx)
- Visual QA renderer: `render_preview.py` (approximate PNG previews in `preview/`, regenerable)
- Assets: `assets/hero_norm.png`, `assets/closing_norm.png` (palette-matched artwork, backgrounds
  normalized to #0719C8)

## Rebuild

```bash
pip install python-pptx pillow numpy
python3 deck/build_deck.py        # writes the .pptx and prints text-overflow warnings
python3 deck/render_preview.py    # optional PNG previews for visual QA
```

## Exact palette used

| Role | HEX |
|---|---|
| Electric Blue (dominant brand) | #0719C8 |
| Vibrant Orange (solution highlights) | #FFAA16 |
| Hot Pink / Magenta (critical emergency) | #F3265B |
| Purple (technical / architecture) | #683C9E |
| Mint Green (success / confirmed) | #58BE98 |
| Yellow (key labels) | #FFD21A |
| Black (dark panels / text on light) | #080808 |
| White (typography / backgrounds) | #FFFFFF |

## Slide map

1. Problem statement + project intro + team (Electric Blue title slide)
2. The real-world problem + core insight
3. Our solution: six-step workflow + three role workspaces
4. Innovation: compatibility matching, verified priority, protected reservations (+3 mechanisms)
5. Technology stack & architecture (Laravel 8/PHP, MySQL/MariaDB, JSON emergency state, Blade/Bootstrap, Sanctum, Mix 6)
6. Live demo workflow: six seeded-demo steps, bed-state chain Hold → Reserved → Occupied, illustrative dashboard mock
7. Security, access control & reliability + stated prototype limitations
8. Business model (explicitly proposed, not existing revenue) + value proposition + pilot-first growth path
9. Three-phase roadmap + current-vs-future capability split (future labelled "planned — not implemented")
10. Impact, vision, team Tech Head, closing statement, Thank You / Questions

## Honesty rules baked into the deck

- No invented statistics, clinical outcomes, market sizes, customers, revenue or partnerships.
- Demo clearly labelled as a seeded prototype (five demo hospitals, predefined distances), and the
  dashboard visual on slide 6 is an **illustrative mock**, not a product screenshot.
- Security slide states prototype limitations verbatim in spirit: validation, authorization, legacy
  endpoints, uploads, password-reset workflows and production security require review.
- Future capabilities are labelled planned/proposed, never implemented.
