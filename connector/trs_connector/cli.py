"""Command line: serve, pull, probe, list, init-config, demo."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .config import EXAMPLE_CONFIG, Config, load_config


def _cfg(args) -> Config:
    path = getattr(args, "config", None)
    if path is None:
        for candidate in ("config.yaml", "config.yml", "/etc/trs-connector/config.yaml"):
            if Path(candidate).exists():
                path = candidate
                break
    return load_config(path)


def cmd_serve(args) -> int:
    import uvicorn
    from .app import create_app
    cfg = _cfg(args)
    if args.host:
        cfg.server.host = args.host
    if args.port:
        cfg.server.port = args.port
    app = create_app(cfg)
    kw = {}
    if cfg.server.tls.certfile and cfg.server.tls.keyfile:
        kw = {"ssl_certfile": cfg.server.tls.certfile, "ssl_keyfile": cfg.server.tls.keyfile}
    uvicorn.run(app, host=cfg.server.host, port=int(cfg.server.port), log_level="info", **kw)
    return 0


def cmd_pull(args) -> int:
    from .exporter import ensure_store, run_pull_blocking
    cfg = _cfg(args)
    store = ensure_store(cfg)
    try:
        m = run_pull_blocking(cfg, store, "cli", args.source)
    except Exception as e:   # noqa: BLE001
        print(f"pull failed: {e}", file=sys.stderr)
        return 1
    print(f"pull {m['id']} complete in {m.get('duration_s')} s: {m.get('summary')}")
    for w in m.get("warnings", []):
        print(f"warning: {w}")
    return 0


def cmd_list(args) -> int:
    from .exporter import ensure_store
    cfg = _cfg(args)
    store = ensure_store(cfg)
    pulls = store.list_pulls(include_failed=True)
    if not pulls:
        print(f"no pulls in {store.root}")
        return 0
    for m in pulls:
        print(f"{m['id']:<22} {m.get('status', '?'):<7} {m.get('finished', '')[:19]:<20} {m.get('summary') or m.get('error', '')}")
    return 0


def cmd_probe(args) -> int:
    """Connectivity and field-mapping report against the real Security Center."""
    from .export_schema import COLUMNS, resolve_mapping
    from .sc_client import SCError, SecurityCenterClient, vuln_filters
    cfg = _cfg(args)
    if not cfg.sc.enabled:
        if cfg.nessus.enabled:
            from .nessus_source import nessus_check
            print(json.dumps(nessus_check(cfg), indent=1))
            return 0
        print("neither sc nor nessus is enabled in the configuration")
        return 1
    try:
        with SecurityCenterClient(cfg.sc.url, cfg.sc.access_key, cfg.sc.secret_key, verify=cfg.sc.verify, timeout=120) as c:
            system = c.system()
            print(f"Security Center {system.get('version')} (build {system.get('buildID')}), license {system.get('licenseStatus')}")
            try:
                u = c.current_user()
                print(f"API key user: {u.get('username')} ({(u.get('role') or {}).get('name') if isinstance(u.get('role'), dict) else u.get('role')})")
            except SCError as e:
                print(f"currentUser: {e}")
            repos = c.repositories()
            print("Repositories: " + ", ".join(f"{r.get('name')} (id {r.get('id')}, {r.get('type')}/{r.get('dataFormat')})" for r in repos))
            page = c.analysis_page({"type": "vuln", "tool": "vulndetails", "filters": vuln_filters(cfg.sc.severities, None, None, None, cfg.sc.extra_filters, cfg.sc.exclude_was)}, 0, 1)
            total = page.get("totalRecords")
            results = page.get("results") or []
            print(f"Vulnerability rows (severities {cfg.sc.severities}): {total}")
            if results:
                rec = results[0]
                mapping = resolve_mapping(rec)
                print("Export columns and the record field they come from:")
                missing = []
                for header, key, cands, _k in COLUMNS:
                    src = mapping.get(header)
                    print(f"  {header:<42} <- {src or '(not in the record)'}")
                    if not src and key:
                        missing.append(header)
                unknown = sorted(k for k in rec.keys() if not any(k == cand.split('.')[0] for _h, _key, cands, _kind in COLUMNS for cand in cands))
                if unknown:
                    print("Record fields with no export column: " + ", ".join(unknown))
                if missing:
                    print("Columns the Studio uses that this Security Center did not return: " + ", ".join(missing))
            page = c.analysis_page({"type": "vuln", "tool": "vulndetails", "filters": vuln_filters(cfg.sc.compliance_severities, None, "compliance", None, None, cfg.sc.exclude_was)}, 0, 1)
            print(f"Compliance rows (severities {cfg.sc.compliance_severities}): {page.get('totalRecords')}")
            try:
                print(f"Accept Risk rules: {len(c.accept_risk_rules())}, Recast Risk rules: {len(c.recast_risk_rules())}")
                scans = c.scan_results(cfg.sc.scan_results_days)
                print(f"Scan results in the last {cfg.sc.scan_results_days} days: {len(scans)}")
            except SCError as e:
                print(f"rules/scans: {e}")
    except SCError as e:
        print(f"Security Center: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_init_config(args) -> int:
    p = Path(args.path)
    if p.exists() and not args.force:
        print(f"{p} exists; use --force to overwrite", file=sys.stderr)
        return 1
    p.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    print(f"wrote {p}")
    return 0


def cmd_demo(args) -> int:
    """Run a synthetic Security Center and the connector against it, for a tour of the Studio
    with the Tenable panel and no real Tenable access."""
    import tempfile
    import uvicorn
    from .app import create_app
    from .mock_sc import create_mock_app
    from .synth import SynthOptions, synth_dataset

    store_dir = args.store or tempfile.mkdtemp(prefix="trs-demo-")
    data = synth_dataset(SynthOptions(hosts=args.hosts, seed=7))
    mock = create_mock_app(data, access_key="demo", secret_key="demo")
    mock_port = args.port + 1
    mock_server = uvicorn.Server(uvicorn.Config(mock, host="127.0.0.1", port=mock_port, log_level="warning"))
    threading.Thread(target=mock_server.run, daemon=True).start()
    cfg = Config()
    cfg.sc.url = f"http://127.0.0.1:{mock_port}"
    cfg.sc.access_key = cfg.sc.secret_key = "demo"
    cfg.store.dir = store_dir
    cfg.schedule.enabled = False
    cfg.server.port = args.port
    if args.config:
        real = load_config(args.config)
        cfg.studio = real.studio
    time.sleep(0.5)
    print(f"demo: synthetic Security Center on http://127.0.0.1:{mock_port} ({len(data['hosts'])} hosts), store {store_dir}")
    print(f"demo: open http://127.0.0.1:{args.port}/ and click Tenable, then Pull now")
    uvicorn.run(create_app(cfg), host=args.host or "127.0.0.1", port=args.port, log_level="info")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="trs-connector", description=f"Tenable Report Studio connector {__version__}")
    ap.add_argument("--config", "-c", help="configuration file (default: ./config.yaml or /etc/trs-connector/config.yaml)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="serve the Studio and the API, run the schedule")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("pull", help="run one pull now and exit")
    s.add_argument("--source", choices=["sc", "nessus"])
    s.set_defaults(fn=cmd_pull)
    s = sub.add_parser("list", help="list the pulls in the store")
    s.set_defaults(fn=cmd_list)
    s = sub.add_parser("probe", help="check the connection and show how the Security Center fields map onto the export columns")
    s.set_defaults(fn=cmd_probe)
    s = sub.add_parser("init-config", help="write an example configuration file")
    s.add_argument("path", nargs="?", default="config.yaml")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init_config)
    s = sub.add_parser("demo", help="serve the Studio against a synthetic Security Center (no Tenable access needed)")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--host")
    s.add_argument("--hosts", type=int, default=60)
    s.add_argument("--store")
    s.set_defaults(fn=cmd_demo)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
