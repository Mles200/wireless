# trs-connector

The service that pulls Tenable Security Center (or Nessus) results on a schedule, keeps them as Studio-ready exports and serves the Tenable Report Studio with a Tenable panel.

```bash
pip install -e .            # or: pip install .
trs-connector demo          # synthetic Security Center + the Studio on http://127.0.0.1:8000
trs-connector init-config   # writes config.yaml
trs-connector probe         # connection and field mapping against the real Security Center
trs-connector pull          # one pull now
trs-connector serve         # the Studio, the API and the weekly schedule
trs-connector list          # the pulls in the store
```

Documentation: `../docs/ARCHITECTURE.md`, `../docs/DEPLOYMENT.md`. Tests: `pip install -e .[test] && pytest`.
