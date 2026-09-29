#!/usr/bin/env python3
"""
connector_monitor.py

Watches a chosen set of Lilt connectors for failed jobs and posts an enriched
alert to Slack: root cause, suggested fix, and a Datadog deep link filtered to
the error lines for that job.

Posts ONLY on failure. Silent when everything is clean.

Usage:
    python connector_monitor.py discover     # probe API paths/auth, run this first
    python connector_monitor.py run          # normal run
    python connector_monitor.py run --dry    # print to stdout, don't post to Slack

Environment:
    LILT_API_KEY        required
    SLACK_WEBHOOK_URL   required (not needed for --dry)
    CONNECTOR_IDS       required, comma separated, e.g. "3478,3477,3462"
    DATADOG_SITE        optional, default us5.datadoghq.com
    STATE_FILE          optional, default ./state.json
    LOOKBACK_HOURS      optional, default 24 (first run only)
    RESUPPRESS_HOURS    optional, default 24

Never logs the API key. Never calls the connector configuration-details
endpoint, which returns live credentials in plaintext.
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

API_ROOT = "https://api.lilt.com/v3"

# ---------------------------------------------------------------------------
# Endpoint paths
#
# CONFIRMED against the live API:
#   auth style: ?key=<API_KEY>   (not Bearer)
#   GET /v3/connectors/configuration/{connector_id}/jobs
#          -> {"limit", "results", "start", "total"}
#   GET /v3/connectors/configuration/jobs/{job_id}
#   GET /v3/connectors/configuration/jobs/{job_id}/workflows
#
# STILL UNKNOWN: the config-validation path. Four GET shapes returned 404.
# Validation is an action, so it is probably a POST. Run `discover` again.
# ---------------------------------------------------------------------------
JOBS_LIST_PATH = "/connectors/configuration/{connector_id}/jobs"   # confirmed
# 16 candidate paths all returned 404. Probably not a public v3 endpoint —
# the MCP server likely composes it internally. Left disabled; the real
# diagnosis comes from the Datadog error lines, not from validation.
VALIDATE_PATH = None
VALIDATE_METHOD = "POST"
JOB_PATH = "/connectors/configuration/jobs/{job_id}"

JOBS_LIST_CANDIDATES = [
    "/connectors/configuration/{connector_id}/jobs",
    "/connectors/configuration/jobs?connector_id={connector_id}",
    "/connectors/{connector_id}/jobs",
]

# (method, path). NOTE: deliberately excludes
# /connectors/configuration/{connector_id} — that endpoint returns live
# credentials in plaintext and must never be called by this script.
VALIDATE_CANDIDATES = [
    ("POST", "/connectors/configuration/{connector_id}/validate"),
    ("POST", "/connectors/configuration/{connector_id}/validation"),
    ("POST", "/connectors/configuration/{connector_id}/validations"),
    ("POST", "/connectors/configuration/validate/{connector_id}"),
    ("POST", "/connectors/configuration/{connector_id}/verify"),
    ("POST", "/connectors/configuration/{connector_id}/test"),
    ("POST", "/connectors/configuration/{connector_id}/check"),
    ("GET", "/connectors/configuration/{connector_id}/validations"),
    ("GET", "/connectors/configuration/{connector_id}/validation-results"),
    ("GET", "/connectors/configuration/{connector_id}/health"),
    ("GET", "/connectors/configuration/{connector_id}/status"),
    ("POST", "/connectors/configuration/{connector_id}/configuration/validate"),
]


# ---------------------------------------------------------------------------
# Rules table — deterministic diagnosis, no model call.
# Ordered: first match wins. Keep the symptom entries LAST.
# ---------------------------------------------------------------------------
def _rclone_path(event: str) -> str:
    """Pull the remote path out of an rclone argv string, best effort."""
    for part in event.split("'"):
        if ":" in part and "/" not in part.split(":")[0] and len(part) > 3:
            if part.split(":")[0].lower() in ("drive", "aws-s3", "s3", "gcs", "sharepoint"):
                return part
    return "(path not parsed)"


RULES = [
    {
        "match": lambda e, v: "is not configured in this inRiver environment" in e
                              or "lilt_external_locale_map" in e,
        "cause": "Target locale not configured in the customer's inRiver environment",
        "fix": lambda e: (
            "Lilt is sending a locale inRiver does not recognise. Either add the "
            "locale in inRiver, or map it via `lilt_external_locale_map` in the "
            "connector config (e.g. {\"es-ES\": [\"es\"]}). "
            + (("Detail: " + e.split("Locale", 1)[1][:220]) if "Locale" in e else "")
        ),
        "klass": "config",
    },
    {
        "match": lambda e, v: "could not resolve target language" in e,
        "cause": "Target language could not be resolved for delivery",
        "fix": "The target language has no equivalent in the downstream system. "
               "Check the connector's locale mapping configuration.",
        "klass": "config",
    },
    {
        "match": lambda e, v: "Connectors secret key does not exist" in (v or ""),
        "cause": "Stored credential missing from the secret store",
        "fix": "The connector's credential is absent, so tokens cannot be refreshed. "
               "Reconnect / re-authorize the connector.",
        "klass": "config",
    },
    {
        "match": lambda e, v: "Error refreshing Google Drive token" in e,
        "cause": "Google OAuth grant expired or revoked",
        "fix": "Ask the customer to re-authorize Google Drive access for this connector.",
        "klass": "credential",
    },
    {
        "match": lambda e, v: "Persistent authentication failure" in e,
        "cause": "Auth still failing after token regeneration",
        "fix": "Re-auth did not resolve it. Escalate to Engineering if it recurs "
               "after a clean reconnect.",
        "klass": "credential",
    },
    {
        "match": lambda e, v: "CalledProcessError(3" in e,
        "cause": "rclone exit 3 — directory not found",
        "fix": lambda e: f"The configured source folder cannot be found.\n  Path: {_rclone_path(e)}\n"
                         "  Likely renamed, moved, or permissions revoked. Ask the customer "
                         "to confirm the current path.",
        "klass": "config",
    },
    {
        "match": lambda e, v: "CalledProcessError(1" in e,
        "cause": "rclone exit 1 — syntax or usage error",
        "fix": lambda e: f"Remote rejected the request.\n  Path: {_rclone_path(e)}\n"
                         "  Check bucket/remote access and credentials.",
        "klass": "config",
    },
    {
        "match": lambda e, v: "protected status" in e,
        "cause": "Contentful refusing writes to protected entries",
        "fix": "Ask the customer to unprotect the affected entries, or exclude them "
               "from the extract query.",
        "klass": "upstream",
    },
    {
        "match": lambda e, v: "Failed to refresh HubSpot access token" in e
                              or "failed to prepare hubspot request headers" in e.lower(),
        "cause": "HubSpot OAuth token could not be refreshed",
        "fix": "The stored refresh token is expired, revoked, or the app was "
               "uninstalled from the customer's HubSpot account. Ask them to "
               "reconnect the HubSpot integration.",
        "klass": "credential",
    },
    {
        "match": lambda e, v: "HTTP client request unauthorized" in e,
        "cause": "HubSpot rejected the request as unauthorized (401)",
        "fix": "Token is invalid or missing required scopes. Reconnect the "
               "integration and confirm the app has the scopes the connector needs.",
        "klass": "credential",
    },
    {
        "match": lambda e, v: "Error fetching resources from HubSpot" in e
                              or "Failed to get resources" in e
                              or "Failed to fetch resources for type" in e,
        "cause": "Could not list content from HubSpot",
        "fix": "Usually follows an auth failure — check for a token error just "
               "before this. If auth is healthy, the content type may not exist "
               "or be visible to the connected app.",
        "klass": "credential",
    },
    {
        "match": lambda e, v: "prose-like fields were not sent for translation" in e,
        "cause": "Some fields were skipped as non-prose",
        "fix": "Expected behaviour, not a failure. If fields are missing from "
               "translation, review the connector's field selection rules.",
        "klass": "upstream",
    },
    {
        "match": lambda e, v: "hubspot api request failed" in e.lower(),
        "cause": "HubSpot API rejected the request",
        "fix": "Verify the HubSpot token and its scopes.",
        "klass": "credential",
    },
    {
        "match": lambda e, v: "Not all files were processed" in e,
        "cause": "Partial success",
        "fix": "Some files failed. Check the Datadog link to see which and why.",
        "klass": "upstream",
    },
    {
        "match": lambda e, v: "SSLError" in e,
        "cause": "TLS failure, probably transient",
        "fix": "Usually self-resolves. Escalate only if it recurs.",
        "klass": "transient",
    },
]

# errorMsg values that are symptoms, never causes.
SYMPTOMS = (
    "There was an issue downloading source files",
    "There was an issue uploading files into LILT",
    "There was an issue uploading translated files",
)


def ask_claude(error_msg, lines, kind, action, org):
    """Diagnose from the log run-up when the rules table has no match.

    Returns (cause, fix, klass) or None. Never raises — enrichment must never
    prevent an alert from going out.
    """
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key or not lines:
        return None

    parts = []
    for l in lines:
        ts = (l.get("ts") or "")[11:19]
        lvl = (l.get("level") or "?")[:5]
        parts.append(f"{ts} [{lvl}] {l.get('raw_event') or l.get('event','')}")
        if l.get("detail"):
            parts.append(f"           error: {l['detail']}")
        if l.get("etype"):
            parts.append(f"           type: {l['etype']}")
        if l.get("src_lang") or l.get("tgt_lang"):
            parts.append(f"           language: {l.get('src_lang','?')} -> {l.get('tgt_lang','?')}")
        if l.get("file"):
            parts.append(f"           file: {l['file']}")
    transcript = "\n".join(parts)[:12000]

    # The final traceback line, if any, is often the single most useful string.
    tb = ""
    for l in reversed(lines):
        if l.get("exception"):
            tail = [p for p in l["exception"].splitlines() if p.strip()]
            if tail:
                tb = f"\nException: {tail[-1].strip()[:500]}"
            break

    prompt = f"""A Lilt connector job failed. Diagnose the root cause.

Connector type: {kind or 'unknown'}
Direction: {action or 'unknown'}
Customer: {org or 'unknown'}
Reported error message: {error_msg}

Log lines leading up to and including the failure, oldest first:

{transcript}{tb}

The reported error message is usually a SYMPTOM naming a phase of the job, not
a cause. The real cause is normally in the lines shortly before the first error,
and is often retried several times before the generic message appears.

Reply with exactly three lines and nothing else:
CAUSE: <one sentence, specific, drawn from the logs>
FIX: <one or two sentences, concretely actionable>
CLASS: <one of: config, credential, upstream, code, transient, unknown>

If the logs do not contain enough to identify a cause, say so in CAUSE and use
CLASS: unknown. Do not speculate beyond what the logs show."""

    body = {
        "model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5"),
        "max_tokens": 400,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
    )
    try:
        timeout = int(os.environ.get("CLAUDE_TIMEOUT", "25"))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        text = "".join(b.get("text", "") for b in data.get("content", []))
    except Exception as e:
        print(f"  CLAUDE lookup failed: {e.__class__.__name__}: {e}", file=sys.stderr)
        return None

    out = {}
    for line in text.splitlines():
        for tag in ("CAUSE", "FIX", "CLASS"):
            if line.strip().upper().startswith(tag + ":"):
                out[tag] = line.split(":", 1)[1].strip()
    if not out.get("CAUSE"):
        return None
    klass = (out.get("CLASS") or "unknown").lower()
    if klass not in ("config", "credential", "upstream", "code", "transient", "unknown"):
        klass = "unknown"
    return out["CAUSE"], out.get("FIX", "See the Datadog link."), klass + " (AI)"


def diagnose(error_msg: str, validation_msg: str, log_events=None):
    """Return (cause, fix, klass).

    Priority: the earliest error line from the logs, then the validation
    message, then errorMsg. errorMsg is usually only a symptom.
    """
    log_events = log_events or []
    cause_line = earliest_cause(log_events)
    haystack = "\n".join(filter(None, [cause_line, validation_msg or "", error_msg]))

    for rule in RULES:
        try:
            if rule["match"](haystack, validation_msg):
                fix = rule["fix"]
                return rule["cause"], (fix(haystack) if callable(fix) else fix), rule["klass"]
        except Exception:
            continue

    # Nothing matched. If we have a real log line, surface it verbatim —
    # far more useful than the symptom, and flags a gap in the rules table.
    if cause_line and not any(s in cause_line for s in SYMPTOMS):
        return (
            cause_line[:300],
            "Not in the rules table. This is the earliest error line for the job — "
            "worth adding a rule if it recurs.",
            "unknown",
        )

    if any(s in error_msg for s in SYMPTOMS):
        return (
            "Unresolved — reported message is a symptom",
            "The reported error names a phase, not a cause. Open the Datadog link and "
            "read the EARLIEST error line; that is the real failure.",
            "unknown",
        )
    return "Not matched by rules table", "Open the Datadog link and review the error lines.", "unknown"


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class Api:
    def __init__(self, key: str):
        self.key = key
        self.mode = None  # "bearer" or "query", set by probe()

    def _open(self, url: str, mode: str, method: str = "GET", body: dict = None):
        data = None
        if mode == "query":
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}key={urllib.parse.quote(self.key)}"
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.key}"})
        if method == "POST":
            data = json.dumps(body or {}).encode()
            req.add_header("Content-Type", "application/json")
        req.data = data
        req.get_method = lambda: method
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw.strip() else {}

    def probe(self) -> str:
        """Determine auth style using a known-good path."""
        url = API_ROOT + JOB_PATH.format(job_id=1)
        for mode in ("bearer", "query"):
            try:
                self._open(url, mode)
                self.mode = mode
                return mode
            except urllib.error.HTTPError as e:
                # 404 means auth passed and the job just doesn't exist. That's success.
                if e.code == 404:
                    self.mode = mode
                    return mode
                if e.code in (401, 403):
                    continue
                self.mode = mode
                return mode
            except Exception:
                continue
        raise SystemExit("Could not authenticate with LILT_API_KEY (tried Bearer and ?key=).")

    def get(self, path: str):
        if self.mode is None:
            self.probe()
        return self._open(API_ROOT + path, self.mode)

    def call(self, method: str, path: str, body: dict = None):
        if self.mode is None:
            self.probe()
        return self._open(API_ROOT + path, self.mode, method=method, body=body)


# ---------------------------------------------------------------------------
# Datadog logs — reads the error lines for a job. Optional: if the two keys
# are absent the script still runs, it just reports the symptom instead of
# the root cause.
# ---------------------------------------------------------------------------
class Datadog:
    """Reads a job's logs. Optional — without the two keys the script still
    runs, it just reports the symptom rather than the root cause."""

    def __init__(self, api_key: str, app_key: str, site: str):
        self.api_key = api_key
        self.app_key = app_key
        self.site = site

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.app_key)

    @staticmethod
    def _iso(ts, pad_seconds=0):
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (dt + timedelta(seconds=pad_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def job_context(self, job_id, created_at: str, updated_at: str, connector_id=None):
        """Return (lines, meta).

        `lines` are dicts: {ts, level, event, svc}, oldest first, combining:
          - error lines for the job from connectors-job
          - the CONTEXT_LINES entries just before the first error, any severity
          - error lines from connectors-configuration-api for this CONNECTOR

        That last source matters: the configuration API logs delivery failures
        with @meta.connectors.id but NO job id, so a job-scoped query misses
        them entirely — including specific ones like "inRiver delivery failed:
        could not resolve target language".
        """
        if not self.enabled:
            return [], {}

        base = (f"service:connectors-job "
                f"@meta.connectors.job.id:{job_id} "
                f"kube_container_name:main ")
        frm = self._iso(created_at, -60)
        to = self._iso(updated_at, 300)
        ctx_n = int(os.environ.get("CONTEXT_LINES", "25"))
        verbose = bool(os.environ.get("VERBOSE"))

        # 1. The job's error lines.
        errors, meta = self._search(base + "@level:error", frm, to, 50, job_id)
        if not errors:
            errors, meta = self._search(
                base + "@level:(error OR warning OR warn)", frm, to, 50, job_id)

        # 2. The run-up: everything before the first error, noise stripped.
        anchor = errors[0]["ts"] if errors else to
        window, meta2 = self._search(
            f"service:connectors-job @meta.connectors.job.id:{job_id}",
            frm, anchor, 400, job_id)
        meta = meta or meta2
        preceding = [r for r in window if not is_noise(r["event"])]
        preceding = preceding[-ctx_n:] if ctx_n > 0 else []

        # 3. Configuration-API delivery errors for this connector. Matched on
        #    connector id, not job id — the service does not log a job id.
        delivery = []
        if connector_id:
            delivery, meta3 = self._search(
                f"service:connectors-configuration-api "
                f"@meta.connectors.id:{connector_id} @level:error env:production",
                frm, to, 50, job_id)
            meta = meta or meta3

        seen, lines = set(), []
        for r in preceding + errors + delivery:
            key = (r["ts"], r["event"])
            if key not in seen:
                seen.add(key)
                lines.append(r)
        lines.sort(key=lambda r: r["ts"] or "")

        if verbose:
            print(f"  DATADOG job {job_id}: {len(errors)} job error(s), "
                  f"{len(preceding)} context, {len(delivery)} delivery error(s)",
                  file=sys.stderr)
        return lines, meta

    def error_events(self, job_id, created_at: str, updated_at: str, limit: int = 50):
        """Backwards-compatible view: just the event strings."""
        lines, meta = self.job_context(job_id, created_at, updated_at)
        return [l["event"] for l in lines], meta

    def _search(self, query: str, frm: str, to: str, limit: int, job_id=None):
        body = {
            "filter": {"query": query, "from": frm, "to": to},
            "sort": "timestamp",          # ascending = oldest first
            "page": {"limit": limit},
        }
        req = urllib.request.Request(
            f"https://api.{self.site}/api/v2/logs/events/search",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "DD-API-KEY": self.api_key,
                "DD-APPLICATION-KEY": self.app_key,
            },
        )
        payload = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    payload = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 3:
                    wait = e.headers.get("X-RateLimit-Reset") or e.headers.get("Retry-After")
                    try:
                        wait = min(int(wait), 60)
                    except (TypeError, ValueError):
                        wait = 5 * (attempt + 1)
                    print(f"  DATADOG 429 — retrying in {wait}s "
                          f"(attempt {attempt + 1}/3)", file=sys.stderr)
                    time.sleep(wait)
                    continue
                detail = ""
                try:
                    detail = e.read().decode()[:300]
                except Exception:
                    pass
                print(f"  DATADOG HTTP {e.code}: {detail}", file=sys.stderr)
                return [], {}
            except Exception as e:
                print(f"  DATADOG lookup failed: {e.__class__.__name__}: {e}",
                      file=sys.stderr)
                return [], {}
        if payload is None:
            print("  DATADOG still rate limited after retries", file=sys.stderr)
            return [], {}

        def dig(d, *names):
            if not isinstance(d, dict):
                return None
            for n in names:
                if n in d and not isinstance(d[n], (dict, list)):
                    return d[n]
            for v in d.values():
                if isinstance(v, dict):
                    got = dig(v, *names)
                    if got is not None:
                        return got
            return None

        rows, meta = [], {}
        for row in payload.get("data", []):
            attrs = row.get("attributes", {}) or {}
            ev = dig(attrs, "event") or attrs.get("message") or ""
            if not ev:
                continue

            # The genuinely diagnostic content lives in meta.error.message and
            # the exception, NOT in `event` — `event` is a generic label like
            # "Platform connector delivery failed". Pull the detail out and
            # append it, so downstream matching and Claude both see it.
            m = attrs.get("attributes", attrs) or {}
            mo = m.get("meta", {}) or {}
            err = mo.get("error", {}) or {}
            detail = (err.get("message") or "").strip()
            etype = (err.get("type") or "").strip()
            exc = (attrs.get("exception") or m.get("exception") or "").strip()

            # Last line of a traceback is the exception itself.
            exc_tail = ""
            if exc:
                parts = [p for p in exc.splitlines() if p.strip()]
                if parts:
                    exc_tail = parts[-1].strip()

            if not detail and exc_tail:
                detail = exc_tail

            full = f"{ev} — {detail}" if detail else ev

            lang = mo.get("language", {}) or {}
            deliv = mo.get("delivery", {}) or {}

            rows.append({
                "ts": attrs.get("timestamp") or m.get("timestamp") or "",
                "level": dig(attrs, "level") or attrs.get("status") or "",
                "event": full,
                "raw_event": ev,
                "detail": detail,
                "etype": etype,
                "exception": exc,
                "svc": row.get("attributes", {}).get("service") or attrs.get("service") or "",
                "src_lang": lang.get("source") or deliv.get("source_language") or "",
                "tgt_lang": lang.get("target") or deliv.get("target_language") or "",
                "file": (deliv.get("filepath") or "").split("/")[-1],
                "correlation": (mo.get("request", {}) or {}).get("correlationId") or "",
            })
            if not meta:
                conn = mo.get("connectors", {}) or {}
                if conn.get("kind"):
                    meta["kind"] = conn["kind"]
                if (conn.get("org") or {}).get("name"):
                    meta["org"] = conn["org"]["name"]
                for key, names in (("kind", ("kind",)), ("org", ("name",)),
                                   ("action", ("action",))):
                    if key not in meta:
                        val = dig(attrs.get("attributes", {}) or {}, *names)
                        if val:
                            meta[key] = val
        return rows, meta


# Routine per-item chatter. These fire hundreds of times per job and never
# explain a failure, so they are dropped before anything is diagnosed.
NOISE_EVENTS = (
    "Adding field",
    "Field is not localized, skip",
    "Entry fields counted",
    "Checking if content is empty",
    "Content is not empty, continuing with download",
    "Connector job heartbeat",
    "Notifying observers",
    "Handling job event",
    "Handling files subject",
    "Loading observers",
    "Registering observer",
    "HTTP Client Request",          # logged with no status code — carries nothing
    "Not handling credit transactions",
    "Skipping target memory update",
    "Fetching Lilt projects",
    "Setting job state",
)


def is_noise(event: str) -> bool:
    return any(n in event for n in NOISE_EVENTS)


def earliest_cause(events):
    """First error line that isn't one of the generic symptom messages."""
    for ev in events:
        if not any(s in ev for s in SYMPTOMS) and not is_noise(ev):
            return ev
    return events[0] if events else ""


# ---------------------------------------------------------------------------
# Datadog deep link — constructed, no Datadog credentials required
# ---------------------------------------------------------------------------
def datadog_link(job_id, created_at: str, updated_at: str, site: str, connector_id=None):
    def ms(ts, pad):
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000) + pad

    # Connector-scoped rather than job-scoped, so the link also surfaces
    # connectors-configuration-api delivery errors, which carry a connector id
    # but no job id.
    #
    # NOTE: no kube_container_name filter here. connectors-job runs in `main`
    # but connectors-configuration-api runs in `lilt-application`, so filtering
    # on either one silently drops half the picture. @level:error is enough to
    # keep the Argo sidecar noise out, since that noise is only tagged on
    # `status`, not `@level`.
    if connector_id:
        query = (f"source:connectors @meta.connectors.id:{connector_id} "
                 f"@level:error")
    else:
        query = (f"service:connectors-job @meta.connectors.job.id:{job_id} "
                 f"kube_container_name:main @level:error")

    params = {
        "query": query,
        "from_ts": ms(created_at, -60_000),
        "to_ts": ms(updated_at, 300_000),
        "live": "false",
        "stream_sort": "asc",
    }
    return f"https://{site}/logs?" + urllib.parse.urlencode(
        params, quote_via=urllib.parse.quote
    )


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {"last_run": None, "alerted": {}}


def save_state(path, state):
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------
def parse_routes(raw: str):
    """Parse ROUTES into an ordered list of (connector_ids, webhook_env_name).

    Format, one rule per line (blank lines and # comments ignored):
        3477,3478 = SLACK_LISA
        1124,813  = SLACK_CS
        *         = SLACK_DEFAULT      # catch-all, optional

    The value is the NAME of an environment variable holding the webhook URL,
    never the URL itself — so URLs stay in secrets and out of the repo.
    """
    routes = []
    for line in (raw or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        ids, env_name = line.split("=", 1)
        ids = [s.strip() for s in ids.split(",") if s.strip()]
        routes.append((ids, env_name.strip()))
    return routes


def webhook_for(connector_id: str, routes, fallback: str):
    """First matching rule wins; '*' matches anything."""
    for ids, env_name in routes:
        if str(connector_id) in ids or "*" in ids:
            url = os.environ.get(env_name, "")
            if url:
                return url
            print(f"  route for {connector_id} points at {env_name}, which is unset",
                  file=sys.stderr)
    return fallback


def post_slack(webhook: str, text: str):
    body = json.dumps({"text": text}).encode()
    req = urllib.request.Request(
        webhook, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status


def format_alert(job, connector_id, cause, fix, klass, dd_url, count):
    kind = job.get("connector_kind") or job.get("kind") or "unknown"
    org = job.get("org_name") or job.get("orgName") or ""
    org_part = f" · {org}" if org else ""
    header = "*There were some errors during a connector job"
    repeat = f"\n:repeat: {count} failures with this same error" if count > 1 else ""
    # Angle brackets are REQUIRED. Without them Slack absorbs following text
    # into the URL and the Datadog query breaks.
    return (
        f"{header}\n"
        f"Connector: `{connector_id}`{org_part} · {kind}\n"
        f"Error: {job.get('errorMsg', '(none)')}\n"
        f"Cause: {cause}\n"
        f"Suggested fix: {fix}\n"
        f"Class: {klass}"
        f"{repeat}\n\n"
        f"DataDog: <{dd_url}>\n"
        f"Admin: <https://connectors-admin.lilt.com/jobs/details?id={job.get('id')}>"
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_discover(api: Api, connector_ids):
    cid = connector_ids[0]
    print(f"Auth mode: {api.probe()}\n")
    print("Probing jobs-list paths:")
    for cand in JOBS_LIST_CANDIDATES:
        path = cand.format(connector_id=cid)
        try:
            data = api.get(path)
            keys = list(data)[:6] if isinstance(data, dict) else f"list[{len(data)}]"
            print(f"  OK   {path}   -> {keys}")
        except urllib.error.HTTPError as e:
            print(f"  {e.code}  {path}")
        except Exception as e:
            print(f"  ERR  {path}  ({e.__class__.__name__})")

    print("\nProbing validate paths (method + path):")
    for method, cand in VALIDATE_CANDIDATES:
        path = cand.format(connector_id=cid)
        try:
            data = api.call(method, path)
            print(f"  OK   {method:4} {path}   -> {str(data)[:160]}")
        except urllib.error.HTTPError as e:
            detail = ""
            if e.code in (400, 422):
                try:
                    detail = "  body: " + e.read().decode()[:120]
                except Exception:
                    pass
            print(f"  {e.code}  {method:4} {path}{detail}")
        except Exception as e:
            print(f"  ERR  {method:4} {path}  ({e.__class__.__name__})")

    print("\nSet VALIDATE_PATH and VALIDATE_METHOD at the top of this file to any OK line.")
    print("A 400 or 422 also counts as found — the path exists but wants a body.")


def extract_jobs(payload):
    """The list endpoint may wrap results; handle the common shapes."""
    if isinstance(payload, list):
        return payload
    for key in ("results", "data", "jobs", "items"):
        if isinstance(payload.get(key), list):
            return payload[key]
    return []


def cmd_run(api: Api, connector_ids, dry: bool):
    site = os.environ.get("DATADOG_SITE", "us5.datadoghq.com")
    state_file = os.environ.get("STATE_FILE", "state.json")
    lookback = int(os.environ.get("LOOKBACK_HOURS", "24"))
    resuppress = int(os.environ.get("RESUPPRESS_HOURS", "24"))
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "")

    routes = parse_routes(os.environ.get("ROUTES", ""))
    if routes:
        named = [i for ids, _ in routes for i in ids if i != "*"]
        if named:
            connector_ids = list(dict.fromkeys(named))
        print(f"Routing: {len(routes)} rule(s), {len(connector_ids)} connector(s)")

    if not dry and not webhook and not routes:
        raise SystemExit("Set SLACK_WEBHOOK_URL or ROUTES (or use --dry).")

    dd = Datadog(
        os.environ.get("DD_API_KEY", ""),
        os.environ.get("DD_APP_KEY", ""),
        site,
    )
    if not dd.enabled:
        print("NOTE: DD_API_KEY / DD_APP_KEY not set — reporting the reported errorMsg "
              "only, without root-cause resolution.", file=sys.stderr)

    state = load_state(state_file)
    now = datetime.now(timezone.utc)
    since = (
        datetime.fromisoformat(state["last_run"])
        if state.get("last_run")
        else now - timedelta(hours=lookback)
    )

    posted = 0
    if os.environ.get("VERBOSE"):
        print(f"Cutoff: only failures newer than {since.isoformat()} "
              f"(last_run={state.get('last_run')})")
    for cid in connector_ids:
        try:
            payload = api.get(JOBS_LIST_PATH.format(connector_id=cid) +
                              ("&" if "?" in JOBS_LIST_PATH else "?") + "status=failed&limit=50")
        except urllib.error.HTTPError as e:
            print(f"connector {cid}: jobs list failed HTTP {e.code} "
                  f"(run `discover` and fix JOBS_LIST_PATH)", file=sys.stderr)
            continue
        except Exception as e:
            print(f"connector {cid}: {e}", file=sys.stderr)
            continue

        jobs = extract_jobs(payload)

        if os.environ.get("VERBOSE"):
            total = payload.get("total") if isinstance(payload, dict) else "?"
            print(f"\n--- connector {cid}: total={total}, parsed {len(jobs)} job(s)")
            if not jobs and isinstance(payload, dict):
                print(f"    payload keys: {list(payload)}")
            for j in jobs[:5]:
                print(f"    status={j.get('status')!r} "
                      f"updatedAt={j.get('updatedAt')!r} "
                      f"errorMsg={str(j.get('errorMsg'))[:60]!r}")
            if jobs:
                print(f"    all fields on first job: {list(jobs[0])}")

        # Only failures newer than the last run.
        fresh = []
        for j in jobs:
            if str(j.get("status", "")).lower() != "failed":
                continue
            ts = j.get("updatedAt") or j.get("createdAt")
            if not ts:
                continue
            try:
                when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
            if when > since:
                fresh.append((when, j))

        if not fresh:
            continue

        # Group by errorMsg; alert once per distinct error.
        groups = {}
        for when, j in fresh:
            groups.setdefault(j.get("errorMsg", ""), []).append((when, j))

        # One validation call per connector, reused across its groups.
        validation_msg = ""
        if VALIDATE_PATH:
            try:
                v = api.call(VALIDATE_METHOD, VALIDATE_PATH.format(connector_id=cid))
                results = v.get("results", v) if isinstance(v, dict) else v
                if isinstance(results, list):
                    validation_msg = " ".join(
                        r.get("message", "") for r in results
                        if str(r.get("status", "")).lower() == "failed"
                    )
            except Exception:
                pass  # validation is best-effort; never block the alert

        for error_msg, entries in groups.items():
            key = f"{cid}::{error_msg}"
            prev = state["alerted"].get(key)
            if prev:
                last = datetime.fromisoformat(prev)
                if (now - last) < timedelta(hours=resuppress):
                    continue

            entries.sort(key=lambda t: t[0], reverse=True)
            _, job = entries[0]
            created = job.get("createdAt", job.get("updatedAt"))
            updated = job.get("updatedAt", job.get("createdAt"))

            log_lines, log_meta = dd.job_context(job.get("id"), created, updated, cid)
            log_events = [l["event"] for l in log_lines]
            if log_meta:
                job.setdefault("connector_kind", log_meta.get("kind"))
                job.setdefault("org_name", log_meta.get("org"))
            cause, fix, klass = diagnose(error_msg, validation_msg, log_events)

            # Rules table missed. Hand the run-up to Claude, which can actually
            # read it. Falls back silently to the rules-table answer on failure.
            if klass == "unknown":
                got = ask_claude(error_msg, log_lines,
                                 job.get("connector_kind"), log_meta.get("action"),
                                 job.get("org_name"))
                if got:
                    cause, fix, klass = got

            dd_url = datadog_link(job.get("id"), created, updated, site, cid)
            text = format_alert(job, cid, cause, fix, klass, dd_url, len(entries))

            if dry:
                target = webhook_for(cid, routes, webhook) if routes else webhook
                print("-" * 70)
                print(f"[would post to: {'routed' if routes else 'default'} webhook"
                      f"{' — MISSING' if not target else ''}]")
                print(text)
            else:
                target = webhook_for(cid, routes, webhook) if routes else webhook
                if not target:
                    print(f"connector {cid}: no webhook configured, skipping",
                          file=sys.stderr)
                    continue
                try:
                    post_slack(target, text)
                except Exception as e:
                    print(f"Slack post failed: {e}", file=sys.stderr)
                    continue
            state["alerted"][key] = now.isoformat()
            posted += 1

    if os.environ.get("CHECK_DELIVERY", "1") != "0":
        posted += delivery_failures(dd, connector_ids, since, now, site, state,
                                    resuppress, routes, webhook, dry)

    state["last_run"] = now.isoformat()
    if not dry:
        save_state(state_file, state)

    # Silent when clean — nothing goes to Slack.
    print(f"{posted} alert(s) {'printed' if dry else 'posted'}.")


def delivery_failures(dd, connector_ids, since, now, site, state, resuppress,
                      routes, webhook, dry):
    """Second detection path: delivery errors that never create a failed job.

    connectors-configuration-api logs per-file delivery failures with a
    connector id but no job id, and the job itself can complete without being
    marked failed. Job-based detection is structurally blind to these, so they
    are polled straight from Datadog instead.
    """
    if not dd.enabled:
        return 0

    posted = 0
    frm = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    to = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    for cid in connector_ids:
        rows, meta = dd._search(
            f"service:connectors-configuration-api @level:error env:production "
            f"@meta.connectors.id:{cid}",
            frm, to, 200, cid)
        if not rows:
            continue

        # All three lines of a single delivery failure carry the same
        # meta.error.message, so grouping on it collapses them into one alert.
        groups = {}
        for r in rows:
            key = r.get("detail") or r.get("raw_event") or r.get("event")
            groups.setdefault(key, []).append(r)

        if os.environ.get("VERBOSE"):
            print(f"--- connector {cid}: {len(rows)} delivery error(s), "
                  f"{len(groups)} distinct", file=sys.stderr)

        for key, entries in groups.items():
            dedupe = f"{cid}::delivery::{key[:120]}"
            prev = state["alerted"].get(dedupe)
            if prev and (now - datetime.fromisoformat(prev)) < timedelta(hours=resuppress):
                continue

            newest = max(entries, key=lambda r: r.get("ts") or "")
            events = [r["event"] for r in entries]
            cause, fix, klass = diagnose("", "", events)
            if klass == "unknown":
                got = ask_claude("(delivery failure — no job-level error message)",
                                 entries[:25], meta.get("kind"), "DELIVERY",
                                 meta.get("org"))
                if got:
                    cause, fix, klass = got

            langs = ""
            if newest.get("tgt_lang"):
                langs = f"\nLanguage: {newest.get('src_lang','?')} → {newest['tgt_lang']}"
            fileline = f"\nFile: `{newest['file']}`" if newest.get("file") else ""

            ddq = (f"source:connectors @meta.connectors.id:{cid} @level:error")
            dd_url = f"https://{site}/logs?" + urllib.parse.urlencode({
                "query": ddq,
                "from_ts": int(since.timestamp() * 1000),
                "to_ts": int(now.timestamp() * 1000),
                "live": "false",
                "stream_sort": "asc",
            }, quote_via=urllib.parse.quote)

            text = (
                f"*Delivery failed — no job was marked failed\n"
                f"Connector: `{cid}`"
                f"{' · ' + meta['org'] if meta.get('org') else ''}"
                f"{' · ' + meta['kind'] if meta.get('kind') else ''}\n"
                f"Error: {newest.get('raw_event','')}\n"
                f"Cause: {cause}\n"
                f"Suggested fix: {fix}\n"
                f"Class: {klass}"
                f"{langs}{fileline}\n"
                f":repeat: {len(entries)} occurrence(s) since {frm}\n\n"
                f"DataDog: <{dd_url}>\n"
                f"Admin: <https://connectors-admin.lilt.com/connectors/{cid}>"
            )

            target = webhook_for(cid, routes, webhook) if routes else webhook
            if dry:
                print("-" * 70)
                print(text)
            else:
                if not target:
                    print(f"connector {cid}: no webhook configured, skipping",
                          file=sys.stderr)
                    continue
                try:
                    post_slack(target, text)
                except Exception as e:
                    print(f"Slack post failed: {e}", file=sys.stderr)
                    continue
            state["alerted"][dedupe] = now.isoformat()
            posted += 1

    return posted


# ---------------------------------------------------------------------------
# Kind-wide activity feed (e.g. every inRiver connector, not a fixed id list)
# ---------------------------------------------------------------------------
# Written to span connector kinds rather than one vendor. Verified against the
# inriver and hubspot vocabularies; new kinds usually reuse these phrasings.
DELIVERY_EVENTS = (
    "Successfully delivered",                  # inriver + hubspot
    "delivery completed successfully",         # hubspot
    "Delivering translated content",           # hubspot
    "Delivering file to connector",            # inriver
    "File delivered successfully",             # hubspot (configuration-api)
    "inRiver field values updated",            # inriver
)
SUBMISSION_EVENTS = (
    "Uploading file to Lilt",
    "Uploaded PackageFile",
    "Batch materialize completed",
    "Successfully materialized",
    "New or changed content detected",         # hubspot
    "File uploaded successfully",              # hubspot (configuration-api)
)
ACTIVITY_NOISE = (
    "HTTP request processed",
    "HTTP Client Request",
    "Checking config secret keyname",
    "Bearer",
    "Establishing direct Redis connection",
    "Saving file to temporary directory",
    "File saved to temporary directory",
    "Downloading file from Lilt",
    "Resource filters applied",
    "Retrieved resource types",
    "Retrieved resources",
    "Starting Inriver entity",
    "Starting batch materialize",
    "Processing file for upload",
    "Connector kind does not track picker jobs",
    # hubspot scheduler chatter — thousands per week, never a failure
    "Skipping schedule",
    "Schedule filtering complete",
    "No schedules need jobs at this time",
    "Processing connector with multiple schedules",
    "Completed multiple schedule processing",
    "Updating next_run",
    "Updated next_run",
    "Processing schedule",
    "index already exists",
    "Database engine",
    "Registering",
    "Loading observers",
    "Notifying observers",
    "Connector job heartbeat",
)


def kind_activity(dd, kind, since, now, site, state, resuppress,
                  routes, webhook, dry, quiet_when_idle=True, only_ids=None):
    """Digest of submissions + deliveries, plus individual enriched error alerts.

    By default this covers EVERY connector of the given kind. Pass `only_ids`
    (from ACTIVITY_CONNECTOR_IDS) to narrow it to specific connectors.
    """
    if not dd.enabled:
        print("kind activity needs DD_API_KEY / DD_APP_KEY", file=sys.stderr)
        return 0

    frm = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    to = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    only_ids = [str(i).strip() for i in (only_ids or []) if str(i).strip()]
    if len(only_ids) == 1:
        scope = f"@meta.connectors.id:{only_ids[0]}"
        label = f"{kind} connector {only_ids[0]}"
    elif only_ids:
        scope = "@meta.connectors.id:(" + " OR ".join(only_ids) + ")"
        label = f"{kind} connectors {', '.join(only_ids)}"
    else:
        scope = f"@meta.connectors.kind:{kind}"
        label = kind

    rows, meta = dd._search(
        f"source:connectors {scope} env:production", frm, to, 1000, None)

    deliveries, submissions, errors = [], [], []
    for r in rows:
        ev = r.get("raw_event") or r.get("event") or ""
        lvl = (r.get("level") or "").lower()
        if any(n in ev for n in ACTIVITY_NOISE) and lvl not in ("error", "critical"):
            continue
        if lvl in ("error", "critical"):
            # `HTTP Client Request` is logged at error with no status code and
            # carries nothing. Its warn-level sibling does carry the 401.
            if "HTTP Client Request" in ev:
                continue
            errors.append(r)
        elif lvl in ("warn", "warning") and "unauthorized" in ev.lower():
            errors.append(r)
        elif any(s in ev for s in DELIVERY_EVENTS):
            deliveries.append(r)
        elif any(s in ev for s in SUBMISSION_EVENTS):
            submissions.append(r)

    if os.environ.get("VERBOSE"):
        print(f"--- {label}: {len(rows)} rows -> {len(submissions)} submission(s), "
              f"{len(deliveries)} delivery(s), {len(errors)} error(s)", file=sys.stderr)

    posted = 0
    target = webhook_for(kind, routes, webhook) if routes else webhook

    def send(text):
        nonlocal posted
        if dry:
            print("-" * 70)
            print(text)
        else:
            if not target:
                print(f"{label}: no webhook configured", file=sys.stderr)
                return
            try:
                post_slack(target, text)
            except Exception as e:
                print(f"Slack post failed: {e}", file=sys.stderr)
                return
        posted += 1

    # --- errors: one enriched alert per distinct cause -------------------
    groups = {}
    for r in errors:
        groups.setdefault(r.get("detail") or r.get("raw_event") or "", []).append(r)

    for key, entries in groups.items():
        dedupe = f"{label}::activity-error::{key[:120]}"
        prev = state["alerted"].get(dedupe)
        if prev and (now - datetime.fromisoformat(prev)) < timedelta(hours=resuppress):
            continue
        newest = max(entries, key=lambda r: r.get("ts") or "")
        cause, fix, klass = diagnose("", "", [r["event"] for r in entries])
        if klass == "unknown":
            got = ask_claude("(activity feed error)", entries[:25], kind, "", "")
            if got:
                cause, fix, klass = got
        ddq = (f"source:connectors @meta.connectors.id:{only_ids[0]} @level:error"
               if len(only_ids) == 1 else
               f"source:connectors @meta.connectors.kind:{kind} @level:error")
        url = f"https://{site}/logs?" + urllib.parse.urlencode({
            "query": ddq, "from_ts": int(since.timestamp() * 1000),
            "to_ts": int(now.timestamp() * 1000), "live": "false",
            "stream_sort": "asc"}, quote_via=urllib.parse.quote)
        send(f"*{label} error\n"
             f"Error: {newest.get('raw_event','')}\n"
             f"Cause: {cause}\n"
             f"Suggested fix: {fix}\n"
             f"Class: {klass}\n"
             f":repeat: {len(entries)} occurrence(s)\n\n"
             f"DataDog: <{url}>")

    # --- successes: one digest, never one message per file ----------------
    if submissions or deliveries:
        delivered = [r for r in deliveries
                     if "Successfully delivered" in (r.get("raw_event") or "")
                     or "completed successfully" in (r.get("raw_event") or "")] or deliveries
        uploaded = [r for r in submissions
                    if "Uploading file to Lilt" in (r.get("raw_event") or "")
                    or "Uploaded PackageFile" in (r.get("raw_event") or "")] or submissions
        langs = sorted({r["tgt_lang"] for r in deliveries if r.get("tgt_lang")})
        files = [r["file"] for r in delivered if r.get("file")][:5]

        lines = [f"*{label} activity — {frm[11:16]} to {to[11:16]} UTC"]
        if uploaded:
            lines.append(f"📤 Submissions to Lilt: {len(uploaded)}")
        if delivered:
            lines.append(f"📥 Deliveries to {kind}: {len(delivered)}")
        if langs:
            lines.append(f"Languages: {', '.join(langs)}")
        if files:
            lines.append("Files: " + ", ".join(f"`{f}`" for f in files)
                         + (" …" if len(delivered) > 5 else ""))
        if errors:
            lines.append(f"⚠️ {len(errors)} error line(s) — see alerts above")
        send("\n".join(lines))
    elif not errors and not quiet_when_idle:
        send(f"*{label} activity — nothing in this window.")

    return posted


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else "run"
    dry = "--dry" in args

    key = os.environ.get("LILT_API_KEY")
    ids = [s.strip() for s in os.environ.get("CONNECTOR_IDS", "").split(",") if s.strip()]

    # `activity` reads Datadog and posts to Slack — it never calls the LILT API,
    # so it needs neither a LILT key nor a connector id list.
    if cmd != "activity":
        if not key:
            raise SystemExit("LILT_API_KEY is not set.")
        if not ids:
            raise SystemExit('CONNECTOR_IDS is not set, e.g. CONNECTOR_IDS="3478,3477"')

    api = Api(key)
    if cmd == "discover":
        cmd_discover(api, ids)
    elif cmd == "activity":
        kind = os.environ.get("CONNECTOR_KIND", "inriver")
        site = os.environ.get("DATADOG_SITE", "us5.datadoghq.com")
        state_file = os.environ.get("STATE_FILE", "state.json")
        hours = int(os.environ.get("LOOKBACK_HOURS", "1"))
        resuppress = int(os.environ.get("RESUPPRESS_HOURS", "24"))
        state = load_state(state_file)
        now = datetime.now(timezone.utc)
        since = (datetime.fromisoformat(state["last_run"])
                 if state.get("last_run") else now - timedelta(hours=hours))
        dd = Datadog(os.environ.get("DD_API_KEY", ""),
                     os.environ.get("DD_APP_KEY", ""), site)
        n = kind_activity(dd, kind, since, now, site, state, resuppress,
                          parse_routes(os.environ.get("ROUTES", "")),
                          os.environ.get("SLACK_WEBHOOK_URL", ""), dry,
                          os.environ.get("QUIET_WHEN_IDLE", "1") != "0",
                          [i for i in os.environ.get("ACTIVITY_CONNECTOR_IDS", "").split(",") if i.strip()])
        state["last_run"] = now.isoformat()
        if not dry:
            save_state(state_file, state)
        print(f"{n} message(s) {'printed' if dry else 'posted'}.")
    elif cmd == "run":
        cmd_run(api, ids, dry)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
