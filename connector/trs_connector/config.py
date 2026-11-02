"""Configuration: a YAML file, with the secrets optionally taken from environment variables.

Every value has a default so that `trs-connector serve` runs with a config file that only
states the Security Center URL and the API keys.  `trs-connector init-config` writes a
commented example.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Info-severity plugins the Studio keeps for the host inventory (OS identification, host
# name, scan information, CPE, OS fingerprint).  A host that only has these rows is listed as
# "scanned, no findings", which is what makes "Validate fixes" conclusive.
INVENTORY_PLUGINS = [11936, 55472, 19506, 45590, 209654]


@dataclass
class SecurityCenterConfig:
    enabled: bool = True
    url: str = ""                      # https://sc.example.local  (port 443 unless stated)
    access_key: str = ""
    secret_key: str = ""
    verify: bool | str = False         # True, False, or the path of the CA bundle that signed the SC certificate
    timeout: float = 600.0             # seconds per API call (large pages of plugin output take a while)
    repositories: list = field(default_factory=list)   # names or ids; empty = every repository
    severities: str = "4,3,2,1"        # vulnerability export: Critical to Low (Info = inventory only, see include_inventory)
    compliance_severities: str = "0,1,2,3,4"   # compliance export: Info (passed), Medium (warning), High (failed)
    include_inventory: bool = True     # add the Info rows of the inventory plugins so hosts without findings stay listed
    inventory_plugins: list = field(default_factory=lambda: list(INVENTORY_PLUGINS))
    page_size: int = 2500              # vulnerability rows per analysis page
    compliance_page_size: int = 1000   # compliance rows carry long plugin output; smaller pages
    sort_field: str = ""               # optional sortField for the analysis query (e.g. "pluginID")
    extra_filters: list = field(default_factory=list)   # [{filterName, operator, value}] added to the vulnerability query
    exclude_was: bool = True           # add wasVuln = excludeWas (web application scanning findings) like pyTenable does
    risk_rules: bool = True            # fetch Accept Risk / Recast Risk rules at every pull
    scan_results: bool = True          # fetch the recent scan results (data freshness) at every pull
    scan_results_days: int = 45


@dataclass
class NessusConfig:
    enabled: bool = False
    url: str = ""                      # https://nessus.example.local:8834
    access_key: str = ""
    secret_key: str = ""
    verify: bool | str = False
    timeout: float = 600.0
    scans: list = field(default_factory=list)   # scan names (or ids) to export; empty = every completed scan in the folder
    folder: str = ""                   # folder name; empty = all folders
    max_age_days: int = 45             # only scans completed within this many days
    export_chunk: int = 1 << 20


@dataclass
class AuthConfig:
    username: str = ""
    password: str = ""                 # empty = no authentication (only acceptable on a closed network segment)


@dataclass
class TLSConfig:
    certfile: str = ""
    keyfile: str = ""


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    auth: AuthConfig = field(default_factory=AuthConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    public_url: str = ""               # how the workstation reaches the service, for the links in the UI and logs


@dataclass
class StoreConfig:
    dir: str = "./data"                # the pulls: one dated folder each
    retention_days: int = 400          # pulls older than this are removed after a successful pull (0 = keep everything)
    compress: bool = True              # keep the CSV files gzip-compressed (served transparently to the browser)


@dataclass
class ScheduleConfig:
    enabled: bool = True
    weekday: str = "Mon"               # Mon..Sun, or "daily"
    time: str = "06:00"                # local time of the timezone below
    timezone: str = "Asia/Riyadh"
    retry_minutes: int = 60            # when a scheduled pull fails, try again after this many minutes (0 = no retry)


@dataclass
class StudioConfig:
    path: str = ""                     # the Studio HTML; default: ../studio/ALTANFEETHI_Tenable_Report_Studio.html
    shared_state: bool = True          # keep report settings and the risk register on the server so the team shares them
    org: str = "ALTANFEETHI"


@dataclass
class Config:
    sc: SecurityCenterConfig = field(default_factory=SecurityCenterConfig)
    nessus: NessusConfig = field(default_factory=NessusConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    store: StoreConfig = field(default_factory=StoreConfig)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    studio: StudioConfig = field(default_factory=StudioConfig)
    source_path: str = ""              # the config file this was read from

    @property
    def studio_path(self) -> Path:
        if self.studio.path:
            return Path(self.studio.path).expanduser()
        here = Path(__file__).resolve().parent
        for candidate in (
            here.parent.parent / "studio" / "ALTANFEETHI_Tenable_Report_Studio.html",
            here / "static" / "studio.html",
        ):
            if candidate.exists():
                return candidate
        return here.parent.parent / "studio" / "ALTANFEETHI_Tenable_Report_Studio.html"


def _fill(obj: Any, data: dict | None) -> Any:
    """Copy the keys of a YAML mapping onto a dataclass instance (nested dataclasses included)."""
    if not data:
        return obj
    for key, value in data.items():
        if not hasattr(obj, key):
            raise ValueError(f"unknown configuration key: {key!r} in {type(obj).__name__}")
        current = getattr(obj, key)
        if hasattr(current, "__dataclass_fields__"):
            _fill(current, value or {})
        else:
            setattr(obj, key, value)
    return obj


ENV_OVERRIDES = {
    "TRS_SC_URL": ("sc", "url"), "TRS_SC_ACCESS_KEY": ("sc", "access_key"), "TRS_SC_SECRET_KEY": ("sc", "secret_key"),
    "TRS_NESSUS_URL": ("nessus", "url"), "TRS_NESSUS_ACCESS_KEY": ("nessus", "access_key"), "TRS_NESSUS_SECRET_KEY": ("nessus", "secret_key"),
    "TRS_AUTH_USERNAME": ("server", "auth", "username"), "TRS_AUTH_PASSWORD": ("server", "auth", "password"),
    "TRS_STORE_DIR": ("store", "dir"), "TRS_PORT": ("server", "port"), "TRS_HOST": ("server", "host"),
    "TRS_STUDIO_PATH": ("studio", "path"),
}


def load_config(path: str | os.PathLike | None) -> Config:
    cfg = Config()
    if path:
        p = Path(path).expanduser()
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{p}: the configuration must be a mapping")
        _fill(cfg, data)
        cfg.source_path = str(p)
        # relative store and studio paths are relative to the config file
        if cfg.store.dir and not Path(cfg.store.dir).is_absolute():
            cfg.store.dir = str((p.parent / cfg.store.dir).resolve())
        if cfg.studio.path and not Path(cfg.studio.path).is_absolute():
            cfg.studio.path = str((p.parent / cfg.studio.path).resolve())
    for env, keys in ENV_OVERRIDES.items():
        value = os.environ.get(env)
        if value is None or value == "":
            continue
        target = cfg
        for key in keys[:-1]:
            target = getattr(target, key)
        current = getattr(target, keys[-1])
        setattr(target, keys[-1], int(value) if isinstance(current, int) and not isinstance(current, bool) else value)
    return cfg


EXAMPLE_CONFIG = """# Tenable Report Studio connector configuration.
# Secrets can stay out of this file: TRS_SC_ACCESS_KEY, TRS_SC_SECRET_KEY, TRS_AUTH_PASSWORD (and the
# other TRS_* variables listed in docs/DEPLOYMENT.md) override the values below.

sc:                                   # Tenable Security Center (REST API, normally port 443)
  enabled: true
  url: https://127.0.0.1              # the connector runs on the Security Center VM; otherwise https://<security-center-host>
  access_key: ""                      # Security Center > Users > (user) > Generate API Keys
  secret_key: ""
  verify: false                       # true, or the path of the CA bundle that signed the Security Center certificate
  repositories: []                    # names or ids; empty = all repositories (the Studio removes cross-repository duplicates)
  severities: "4,3,2,1"               # vulnerability export: Critical to Low
  include_inventory: true             # add the Info rows of the inventory plugins so hosts with no findings stay listed
  page_size: 2500
  compliance_page_size: 1000

nessus:                               # optional: Nessus / Nessus Manager on port 8834, used when Security Center is not the source
  enabled: false
  url: https://127.0.0.1:8834
  access_key: ""
  secret_key: ""
  verify: false
  scans: []                           # scan names to export; empty = every completed scan of the last max_age_days
  max_age_days: 45

server:
  host: 0.0.0.0
  port: 8000
  public_url: http://<tenable-vm>:8000   # how the workstation reaches the service
  auth:
    username: studio                  # HTTP basic authentication for the Studio and the API (leave both empty to disable)
    password: ""                      # or TRS_AUTH_PASSWORD
  tls:
    certfile: ""                      # optional: serve HTTPS (see docs/DEPLOYMENT.md for a self-signed certificate)
    keyfile: ""

store:
  dir: ./data                         # every pull in its own dated folder
  retention_days: 400
  compress: true

schedule:
  enabled: true
  weekday: Mon                        # Mon..Sun or daily
  time: "06:00"
  timezone: Asia/Riyadh
  retry_minutes: 60

studio:
  path: ""                            # default: ../studio/ALTANFEETHI_Tenable_Report_Studio.html
  shared_state: true                  # report settings and the risk register are kept on the server and shared by the team
  org: ALTANFEETHI
"""
