"""Generate mcl-sentinel's two C4 diagrams into assets/.

Run:  python3 architecture/c4_diagrams.py

  c4-context.svg     Level 1: what the service talks to
  c4-components.svg  Level 2: what it is made of

Drawn from the code, never from a template: the callbacks in
mcl_sentinel_service.erl, the children and their order in mcl_sentinel_sup.erl,
the store in mcl_sentinel_store.erl, the ingest in hear_warden_reports.erl and
warden_report.erl, the record_threat slice, the read model in
query_threats/sentinel_threats.erl, enrichment in enrich_attackers/, the fact
contract in mcl_sentinel_facts.erl, the dependencies in rebar.config, and the
environment in config/sys.config.src, the Containerfile and
deploy/docker-compose.yml. When one of those changes, the diagram changes in the
same commit.

Colours are plain classes with a prefers-color-scheme: dark block, no CSS custom
properties (rsvg-convert renders those black), so the SVGs render the same on
GitHub, in IDE previews and through rsvg-convert. After a change, render each
(rsvg-convert -w 1400 assets/c4-context.svg -o /tmp/c.png) and look at it; keep
architecture/README.md's tables in step.
"""
import os
from xml.sax.saxutils import escape

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets")

SANS = '"Atkinson Hyperlegible", "Segoe UI", system-ui, -apple-system, Helvetica, Arial, sans-serif'
MONO = '"JetBrains Mono", ui-monospace, Menlo, Consolas, monospace'

# Element kinds, each (light fill, light stroke, dark fill, dark stroke).
KINDS = {
    "b-sys": ("#F5E9CC", "#A56F0A", "#3A2E13", "#E3AA3C"),   # in scope
    "b-per": ("#E3EBF2", "#3B5B7A", "#1D2A36", "#8EB4D8"),   # person
    "b-mac": ("#E6E4EE", "#5E5A78", "#26243A", "#A9A4C8"),   # Macula infrastructure
    "b-ext": ("#ECEFED", "#8A9791", "#1C2421", "#7D8B85"),   # external system
    "b-cmp": ("#FFFFFF", "#8A9791", "#171F1C", "#7D8B85"),   # component or container
}

STYLE = f"""<style>
.t-name {{ font-family: {SANS}; font-size: 15px; font-weight: 700; }}
.t-desc {{ font-family: {SANS}; font-size: 12.5px; }}
.t-rel {{ font-family: {SANS}; font-size: 11.5px; paint-order: stroke; stroke-width: 4px; stroke-linejoin: round; }}
.t-code {{ font-family: {MONO}; font-size: 13px; font-weight: 600; }}
.t-type {{ font-family: {MONO}; font-size: 11.5px; }}
.t-bound {{ font-family: {MONO}; font-size: 12px; font-weight: 600; }}
.t-leg {{ font-family: {SANS}; font-size: 12px; }}
.edge {{ fill: none; stroke-width: 1.25; }}
.edge-later {{ fill: none; stroke-width: 1.25; stroke-dasharray: 5 4; }}
.bg {{ fill: #FFFFFF; }}
""" + "".join(f".{k} {{ fill: {v[0]}; stroke: {v[1]}; stroke-width: {2 if k == 'b-sys' else 1.25}; }}\n" for k, v in KINDS.items()) + """\
.b-later { fill: none; stroke: #8A9791; stroke-width: 1.25; stroke-dasharray: 5 4; }
.bound { fill: none; stroke: #B3BDB8; stroke-width: 1; }
.head { fill: #3B5B7A; }
.t-name, .t-code { fill: #16201D; }
.t-type, .t-bound, .t-leg { fill: #66736E; }
.t-desc { fill: #34413C; }
.t-rel { fill: #66736E; stroke: #FFFFFF; }
.edge, .edge-later { stroke: #8A9791; }
.arrowhead { fill: #8A9791; }
@media (prefers-color-scheme: dark) {
.bg { fill: #171F1C; }
""" + "".join(f".{k} {{ fill: {v[2]}; stroke: {v[3]}; }}\n" for k, v in KINDS.items()) + """\
.b-later { stroke: #7D8B85; }
.bound { stroke: #4A5752; }
.head { fill: #8EB4D8; }
.t-name, .t-code { fill: #E6ECE9; }
.t-type, .t-bound, .t-leg { fill: #93A09A; }
.t-desc { fill: #C3CDC8; }
.t-rel { fill: #93A09A; stroke: #171F1C; }
.edge, .edge-later { stroke: #7D8B85; }
.arrowhead { fill: #7D8B85; }
}
</style>"""

DEFS = ('<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
        'orient="auto-start-reverse"><path class="arrowhead" d="M0 0L10 5L0 10z"/></marker></defs>')

LEGEND = [("b-sys", "In scope"), ("b-per", "Person"), ("b-mac", "Macula infrastructure"),
          ("b-ext", "External system"), ("b-cmp", "Container or component")]
BOUNDARY = ("bound", "Boundary")


class Diagram:
    def __init__(self, name, title, w, h):
        self.name, self.title, self.w, self.h, self.parts = name, title, w, h, []

    def text(self, cls, x, y, s, anchor=None, rotate=None):
        a = f' text-anchor="{anchor}"' if anchor else ""
        r = f' transform="rotate({rotate} {x} {y})"' if rotate is not None else ""
        self.parts.append(f'<text class="{cls}" x="{x}" y="{y}"{a}{r}>{escape(s)}</text>')

    def box(self, cls, x, y, w, h, name, kind, desc, person=False, code=False):
        # A box that is too small for its own words renders as text on top of the
        # next box, which no test would catch and a reader would read as the
        # diagram saying something it does not. Fail here instead.
        need = 70 + 16 * max(len(desc) - 1, 0) + 18
        if h < need:
            raise ValueError(f"{self.name}: {name} needs height {need}, has {h}")
        for line in desc:
            if 16 + 6.2 * len(line) > w - 16:
                raise ValueError(f"{self.name}: {name}: '{line}' is wider than {w - 32}px")
        self.parts.append(f'<rect class="{cls}" x="{x}" y="{y}" width="{w}" height="{h}" rx="10"/>')
        tx = x + 16
        if person:
            self.parts.append(f'<circle class="head" cx="{x + 26}" cy="{y + 24}" r="9"/>')
            tx = x + 44
        self.text("t-code" if code else "t-name", tx, y + 28, name)
        self.text("t-type", tx, y + 46, kind)
        for i, line in enumerate(desc):
            self.text("t-desc", x + 16, y + 70 + 16 * i, line)

    def bound(self, x, y, w, h, label):
        self.parts.append(f'<rect class="bound" x="{x}" y="{y}" width="{w}" height="{h}" rx="12"/>')
        self.text("t-bound", x + 16, y + 22, label)

    def edge(self, d, later=False):
        self.parts.append(f'<path class="{"edge-later" if later else "edge"}" d="{d}" marker-end="url(#a)"/>')

    def legend(self, y, boundary=True):
        x = 24
        for cls, label in LEGEND + ([BOUNDARY] if boundary else []):
            self.parts.append(f'<rect class="{cls}" x="{x}" y="{y}" width="22" height="14" rx="3"/>')
            self.text("t-leg", x + 30, y + 12, label)
            x += 34 + 6.6 * len(label)

    def write(self):
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" role="img" '
               f'aria-label="{escape(self.title)}">', f"<title>{escape(self.title)}</title>", STYLE, DEFS,
               f'<rect class="bg" x="0" y="0" width="{self.w}" height="{self.h}"/>'] + self.parts + ["</svg>", ""]
        with open(os.path.join(OUT, self.name), "w") as f:
            f.write("\n".join(svg))


def context():
    d = Diagram("c4-context.svg", "mcl-sentinel system context", 1200, 810)
    d.box("b-per", 60, 60, 300, 104, "Service operator", "[Person]",
          ["Deploys the release, lists the", "wardens, mounts the DB-IP files"], person=True)
    d.box("b-ext", 760, 60, 320, 120, "Threat commons consumers", "[External system, mesh services]",
          ["Any mesh service that wants to", "know who is attacking: it reads",
           "the four facts on the realm"])
    d.box("b-ext", 40, 320, 280, 110, "DB-IP Lite", "[External system]",
          ["dbip-city-lite.mmdb and", "dbip-asn-lite.mmdb, at /geoip"])
    d.box("b-sys", 380, 300, 360, 150, "mcl-sentinel", "[mcl_om mesh service, own box]",
          ["Hears configured wardens, records", "each sighting, names a campaign",
           "when a second warden sees the", "address, and publishes four facts"])
    d.box("b-ext", 800, 300, 320, 110, "Event store", "[External system, host directory]",
          ["/data holds the reckon-db store:", "threat_sighted_v1 is the evidence"])
    d.box("b-ext", 60, 540, 300, 140, "Warden boxes", "[External system, mcl-warden]",
          ["The wardens this sentinel is", "configured with publish",
           "attacker_sighted and attacker_ensnared"])
    d.box("b-mac", 400, 540, 340, 120, "macula-realm", "[Macula infrastructure]",
          ["Endorses the node's identity key", "and grants the one scope it asks",
           "for, mcl-sentinel"])
    d.box("b-mac", 800, 540, 320, 120, "Macula stations, mesh DHT", "[Macula infrastructure]",
          ["The pinned stations are its mesh", "entry points over QUIC; the facts",
           "go out through them"])
    d.edge("M210 164V240H420V300")
    d.text("t-rel", 218, 200, "deploys; lists the wardens")
    d.edge("M700 300V220H900V180")
    d.text("t-rel", 908, 210, "publishes four facts")
    d.edge("M320 375H380")
    d.text("t-rel", 48, 312, "reads dbip-city-lite.mmdb")
    d.edge("M740 355H800")
    d.text("t-rel", 748, 292, "writes threat_sighted_v1")
    d.edge("M210 540V490H440V450")
    d.text("t-rel", 218, 462, "publishes attacker_sighted and")
    d.text("t-rel", 218, 478, "attacker_ensnared")
    d.edge("M560 450V540")
    d.text("t-rel", 568, 500, "boot claim, scope mcl-sentinel")
    d.edge("M740 420H780V520H900V540")
    d.text("t-rel", 788, 440, "the four facts go out")
    d.text("t-rel", 788, 456, "over the mesh")
    d.text("t-desc", 60, 710, "The sentinel applies nothing and holds no lock: it reads what wardens publish, keeps the evidence in its own store, and publishes what it recorded.")
    d.text("t-desc", 60, 728, "Only a configured warden is heard, by the publisher macula verified, never by anything the payload claims about itself. The record is the evidence an abuse report is built from.")
    d.text("t-desc", 60, 746, "Geolocation is additive: with no DB-IP files, the facts carry no country, city or ASN, and nothing else changes. IP geolocation by DB-IP, CC BY 4.0.")
    d.legend(770, boundary=False)
    d.write()


def components():
    d = Diagram("c4-components.svg", "mcl-sentinel components", 1200, 1300)
    d.bound(16, 40, 1168, 986, "mcl-sentinel [Container: one OTP release]")
    d.box("b-cmp", 40, 66, 480, 120, "mcl_sentinel_app", "[application behaviour]",
          ["start/2 opens the store, then boots:", "mcl_sentinel_store:open(event_store()),",
           "then mcl_om:boot(mcl_sentinel_service)"], code=True)
    d.box("b-cmp", 660, 66, 500, 120, "mcl_sentinel_service", "[mcl_om_service behaviour]",
          ["info, start, stop, health, capabilities,", "identity_spec, plus event_store/0 and",
           "hearing/1. capabilities/0 is []"], code=True)
    d.box("b-cmp", 40, 210, 480, 104, "mcl_sentinel_store", "[reckon-db store + evoq subscription]",
          ["Starts the store at MCL_DATA_DIR, waits", "until reckon_db lists it, subscribes evoq"],
          code=True)
    d.box("b-cmp", 660, 210, 500, 104, "mcl_sentinel_sup", "[supervisor, rest_for_one]",
          ["Three children in order: sentinel_enrich,", "sentinel_threats, hear_warden_reports"],
          code=True)
    d.box("b-cmp", 40, 338, 480, 120, "hear_warden_reports", "[gen_server, the only subscriber]",
          ["Subscribes to both warden topics; attributes", "each fact, records it, folds it, and publishes",
           "attacker_sighted and campaign_detected"], code=True)
    d.box("b-cmp", 660, 338, 500, 120, "mcl_sentinel_facts", "[the public contract, pure]",
          ["The four topics, their payloads, the realm", "name check and publish/2; it keeps no state"],
          code=True)
    d.box("b-cmp", 40, 482, 480, 120, "maybe_report_threat", "[the report_threat handler]",
          ["Validates the address, emits threat_sighted_v1,", "derives sighting_id/4 from the observation,",
           "dispatches through evoq_command_router"], code=True)
    d.box("b-cmp", 660, 482, 500, 120, "warden_report", "[pure, the admission gate]",
          ["wardens/0 parses MCL_SENTINEL_WARDENS;", "attribute/4 takes a report only when the",
           "verified publisher is on that list"], code=True)
    d.box("b-cmp", 40, 626, 480, 104, "threat_sighted_v1", "[evoq_event, the evidence]",
          ["One event per sighting stream; immutable,", "attributed to the warden that signed it"],
          code=True)
    d.box("b-cmp", 660, 626, 500, 104, "threat_aggregate", "[evoq_aggregate + sighting_state]",
          ["One stream per sighting; a redelivered", "observation is refused here with {ok, []}"],
          code=True)
    d.box("b-cmp", 40, 754, 480, 104, "sentinel_threats", "[gen_server, ETS read model]",
          ["Keyed by source address; rebuilt from the log", "once at boot, then folded by ingest only"],
          code=True)
    d.box("b-cmp", 660, 754, 500, 104, "sentinel_enrich", "[gen_server + locus]",
          ["Loads the DB-IP city and ASN files before", "the read model starts; lookup/1 is additive"],
          code=True)
    d.box("b-mac", 40, 882, 360, 120, "mcl_om", "[library, ~> 1.4]",
          ["boot/1 wires mesh, identity, health;", "publishes through mcl_om_pubsub"], code=True)
    d.box("b-mac", 420, 882, 360, 120, "macula", "[library, ~> 16.0]",
          ["subscribe/4, the topic names, the wire", "codec, and the signed DHT records"], code=True)
    d.box("b-mac", 800, 882, 360, 120, "reckon_db, evoq, reckon_evoq", "[libraries]",
          ["the store, the aggregate, command and", "event behaviours; locus reads the DB-IP files"],
          code=True)
    d.box("b-ext", 40, 1056, 1120, 104, "the host environment", "[environment, read at boot; no secret here]",
          ["MCL_SENTINEL_WARDENS (the only callers whose reports are taken), MCL_SENTINEL_GEOIP (/geoip, set in the Containerfile), MCL_DATA_DIR;",
           "MCL_REALM, MCL_REALM_NAME, MCL_REALM_KEY and the station pins are read by mcl_om at boot, not by these modules"],
          code=True)
    d.edge("M520 126H660"); d.text("t-rel", 590, 118, "boots", anchor="middle")
    d.edge("M285 186V210"); d.text("t-rel", 293, 206, "opens the store first")
    d.edge("M915 186V210"); d.text("t-rel", 923, 206, "start/1")
    d.edge("M660 262H620V310H440V338"); d.text("t-rel", 528, 302, "starts its children")
    d.edge("M520 398H660"); d.text("t-rel", 528, 390, "publish/2")
    d.edge("M520 430H590V500H660"); d.text("t-rel", 528, 470, "attribute/4")
    d.edge("M285 458V482"); d.text("t-rel", 293, 478, "a sighting")
    d.edge("M520 550H590V686H660"); d.text("t-rel", 528, 566, "executes it")
    d.edge("M285 602V626"); d.text("t-rel", 293, 622, "emits")
    d.edge("M520 792H660"); d.text("t-rel", 560, 784, "lookup/1")
    d.text("t-desc", 40, 1190, "The read model has no projection on purpose: evoq replays the whole log to every handler on each boot, so a projection would fold")
    d.text("t-desc", 40, 1208, "history twice and announce every old campaign again. The ingest is the only folder after boot, and the only publisher of facts.")
    d.text("t-desc", 40, 1226, "The three library boxes are drawn without arrows: boot and publish/2 go through mcl_om, while the subscriber calls macula:subscribe/4 and the facts module builds topics with macula_topic, both directly. locus is called only by sentinel_enrich.")
    d.legend(1250)
    d.write()


if __name__ == "__main__":
    for make in (context, components):
        make()
