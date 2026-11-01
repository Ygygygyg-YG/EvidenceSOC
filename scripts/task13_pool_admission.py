"""Produce one actual, zero-provider pool admission. Never sends GO or registers state.

Use python -m scripts.task13_pool_admission --manifest PATH --manifest-sha256 SHA
--trial-id NEXT_TRIAL --service-env ROOT/.env. All outputs are exclusive under the
approved free_admission.gate_root. Requires adopted native hosts and a prepared
pool journal; reader evidence and original public baseline are scope-pinned.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import os
import re
import sqlite3
import ssl
import subprocess
import time
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

URLS = {
    "official-pricing": "https://api-docs.deepseek.com/zh-cn/quick_start/pricing/",
    "official-thinking-mode": "https://api-docs.deepseek.com/zh-cn/guides/thinking_mode/",
}


def require(value, reason):
    if not value:
        raise PermissionError(reason)


def clean_environment(environment=None):
    environment = os.environ if environment is None else environment
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC", "PATHEXT"}
    return {k: v for k, v in environment.items() if k.upper() in allowed}


def pin(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}


def checked(reference):
    from scripts.task13_e_trial import _decode, _read_pin

    return _decode(_read_pin(reference))


def write_raw(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return pin(path)


def write_json(path, value):
    return write_raw(
        path,
        (
            json.dumps(
                value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
            )
            + "\n"
        ).encode(),
    )


def service_environment(path):
    """Parse only selected lines, never provider values or dotenv interpolation."""
    from dotenv import dotenv_values
    from sqlalchemy.engine import make_url

    selected = []
    with Path(path).open(encoding="utf-8-sig") as stream:
        for line in stream:
            if re.match(r"^\s*(?:export\s+)?(?:DATABASE_URL|OPENSEARCH_URL)\s*=", line):
                selected.append(line)
    require(len(selected) == 2, "exactly two service settings required")
    values = dotenv_values(stream=io.StringIO("".join(selected)), interpolate=False)
    require(
        set(values) == {"DATABASE_URL", "OPENSEARCH_URL"}, "service setting duplicate"
    )
    database = make_url(values["DATABASE_URL"])
    search = urlsplit(values["OPENSEARCH_URL"])
    require(database.get_backend_name() == "postgresql", "PostgreSQL required")
    require(
        database.host in {"localhost", "127.0.0.1", "::1", "evidencesoc-postgres-1"}
        and database.port in {None, 5432},
        "unapproved database endpoint",
    )
    require(
        not {"host", "port", "hostaddr", "service", "servicefile"}.intersection(
            database.query
        ),
        "database endpoint override",
    )
    require(
        search.scheme in {"http", "https"}
        and (
            (
                search.hostname in {"localhost", "127.0.0.1", "::1"}
                and search.port == 9201
            )
            or (search.hostname == "evidencesoc-opensearch-1" and search.port == 9200)
        )
        and search.path in {"", "/"}
        and not search.query
        and not search.fragment,
        "unapproved search endpoint",
    )
    auth = search.netloc.rsplit("@", 1)[0] + "@" if "@" in search.netloc else ""
    return {
        "DATABASE_URL": database.set(
            host="evidencesoc-postgres-1", port=5432
        ).render_as_string(hide_password=False),
        "OPENSEARCH_URL": urlunsplit(
            (search.scheme, auth + "evidencesoc-opensearch-1:9200", "", "", "")
        ),
    }


def docker_runner(environment):
    def docker(arguments, timeout=30, check=True):
        return subprocess.run(
            ["docker", *arguments],
            env=environment,
            capture_output=True,
            timeout=timeout,
            check=check,
        )

    return docker


SERVICE_INSPECT_TEMPLATE = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
    '"Config":{"Image":{{json .Config.Image}},"User":{{json .Config.User}},'
    '"Hostname":{{json .Config.Hostname}},"Labels":{{json .Config.Labels}},'
    '"Cmd":{{json .Config.Cmd}},"Entrypoint":{{json .Config.Entrypoint}},'
    '"EnvNames":[{{range $i,$v := .Config.Env}}{{if $i}},{{end}}'
    '{{json (index (split $v "=") 0)}}{{end}}]},'
    '"HostConfig":{{json .HostConfig}},"Mounts":{{json .Mounts}},"State":{{json .State}}}'
)


def inspect_arguments(identity, *, service=False):
    return ["inspect", identity] + (
        ["--format", SERVICE_INSPECT_TEMPLATE] if service else []
    )


def inspection_value(raw, *, service=False):
    value = json.loads(raw)
    if service:
        require(isinstance(value, dict), "projected inspection must be one object")
        return value
    require(
        isinstance(value, list) and len(value) == 1,
        "exactly one inspected container required",
    )
    return value[0]


def recording_docker(docker, out):
    events = []

    def recorded(arguments, **kwargs):
        check = kwargs.pop("check", True)
        result = docker(arguments, check=False, **kwargs)
        index = len(events)
        event = {
            "argv": list(arguments),
            "returncode": result.returncode,
            "stdout": write_raw(out / f"docker-{index:03d}.stdout.bin", result.stdout),
            "stderr": write_raw(
                out / f"docker-{index:03d}.stderr.bin", getattr(result, "stderr", b"")
            ),
            "recorded_at": datetime.now(UTC).isoformat(),
        }
        events.append(event)
        if check and result.returncode != 0:
            raise PermissionError("Docker command failed; raw receipt retained")
        return result

    recorded.events = events
    return recorded


def cleanup_owned(docker, name, nonce, *, service=False):
    """Only remove an inspected full ID carrying this invocation's nonce/name."""
    inspected = docker(inspect_arguments(name, service=service), check=False)
    if inspected.returncode == 0:
        info = inspection_value(inspected.stdout, service=service)
        require(
            info["Name"] == "/" + name
            and info["Config"]["Labels"].get("task13.free.nonce") == nonce
            and re.fullmatch("[a-f0-9]{64}", info["Id"]),
            "cleanup ownership mismatch",
        )
        docker(["rm", "--force", info["Id"]])
    remaining = docker(
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            "name=^/" + name + "$",
            "--format",
            "{{.ID}}",
        ]
    )
    require(not remaining.stdout.strip(), "owned container remains")
    return True


def mount_identity(info):
    """Docker's Mounts array order is unspecified; retain every field by target."""
    mounted = {item["Destination"]: item for item in info["Mounts"]}
    require(len(mounted) == len(info["Mounts"]), "duplicate container mount target")
    return mounted


def inspect_container(info, *, name, nonce, runtime, network, mounts):
    mount_identity(info)
    require(
        info["Name"] == "/" + name
        and info["Config"]["Labels"].get("task13.free.nonce") == nonce,
        "container ownership differs",
    )
    require(
        info["Image"] == runtime["image_id"]
        and info["Config"]["Image"] == runtime["image_id"],
        "image differs",
    )
    config = info["HostConfig"]
    require(
        config["NetworkMode"] == network
        and config["ReadonlyRootfs"] is True
        and info["Config"]["User"] == "65532:65532"
        and config["CapDrop"] == ["ALL"]
        and "no-new-privileges" in config["SecurityOpt"],
        "container isolation differs",
    )
    mounted = {
        item["Destination"]: item for item in info["Mounts"] if item["Type"] == "bind"
    }
    require(
        len(mounted) == sum(item["Type"] == "bind" for item in info["Mounts"])
        and all(
            item["Type"] == "bind"
            or (
                item["Type"] == "tmpfs"
                and item["Destination"] == "/tmp"
                and item["RW"] is True
            )
            for item in info["Mounts"]
        ),
        "unapproved extra or duplicate container mount",
    )
    require(
        set(mounted) == {target for _, target, _ in mounts}, "bind mount set differs"
    )
    for source, target, readonly in mounts:
        item = mounted[target]
        # Docker Desktop reports bind sources as Linux /run/desktop/mnt/host/d/... .
        observed = item["Source"].replace("\\", "/").casefold()
        expected = str(Path(source).resolve()).replace("\\", "/").casefold()
        translated = (
            "/run/desktop/mnt/host/" + expected[0] + expected[2:]
            if len(expected) > 1 and expected[1] == ":"
            else expected
        )
        require(
            observed in {expected, translated} and item["RW"] is (not readonly),
            "bind source/mode differs",
        )
    require(
        not any(
            re.match(r"(?:DEEPSEEK|OPENAI|ANTHROPIC).*KEY$", item.split("=", 1)[0])
            for item in info["Config"].get("EnvNames", info["Config"].get("Env", []))
        ),
        "provider credential present",
    )


def copy_sqlite(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    with (
        sqlite3.connect(
            Path(source).resolve().as_uri() + "?mode=ro", uri=True
        ) as original,
        sqlite3.connect(target) as copied,
    ):
        original.backup(copied)


async def native_probe(host, request, out):
    """Run the frozen worker main through its complete pre-GO handshake only."""
    from scripts.task13_worker_runtime import (
        e_planning_runtime_binding,
        validate_e_planning_probe,
        validate_worker_binding,
    )

    runtime = host._inputs["runtime_options"]
    original_budget = Path(runtime["budget_dir"]) / "campaign.sqlite"
    authority = host._inputs["planning_authority"]
    copy_sqlite(original_budget, out / "budget/campaign.sqlite")
    copy_sqlite(Path(authority["journal_path"]), out / "dispatch/e-planning.sqlite")
    dependency = json.loads(
        (Path(runtime["dependencies_dir"]) / "task13_dependencies.json").read_bytes()
    )
    runtime_binding = e_planning_runtime_binding(runtime, dependency)
    spec = out / "spec.json"
    write_json(spec, request.model_dump(mode="json"))
    require(
        sha256((host._agent / "events.jsonl").read_bytes()).hexdigest()
        == request.agent_sha256,
        "original case events changed",
    )
    forbidden = {}
    for kind in ("scoring", "git", "other_case"):
        canary = out / kind / "canary.txt"
        canary.parent.mkdir()
        write_raw(canary, uuid.uuid4().hex.encode())
        # Linux treats Windows backslashes as literal filename characters. Long
        # COW roots would become one >255-byte component instead of an absent path.
        forbidden[kind] = [canary.resolve().as_posix(), "/app/" + kind + "/canary.txt"]
    forbidden["git"] += ["/app/source/.git/config", "/.git/config"]
    nonce = uuid.uuid4().hex
    name = "task13-free-startup-" + nonce
    envs = {
        "PYTHONPATH": "/app/source:/app/source/services/backend/src:/opt/task13-deps",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TASK13_SOURCE_DIR": "/app/source",
        "TASK13_SOURCE_COMMIT": request.source_commit,
        "TASK13_BUDGET_DB": "/app/budget/campaign.sqlite",
        "TASK13_EPOCH_HOST_BUDGET_PATH": str(original_budget.resolve()),
        "TASK13_IMPORT_SOURCE_DIR": "/app/import-source",
        "TASK13_IMPORT_DISPATCH_DB": "/app/import-dispatch/e-planning.sqlite",
        "TASK13_IMPORT_HOST_JOURNAL_PATH": authority["journal_path"],
        "TASK13_IMPORT_AUTHORITY_SHA256": runtime["planning_authority_sha256"],
        "TASK13_RUNTIME_BINDING": json.dumps(runtime_binding, sort_keys=True),
        "TASK13_FORBIDDEN_PATHS": json.dumps(forbidden),
        "TASK13_OUTPUT_DIR": "/app/output",
        "OPENBLAS_NUM_THREADS": "1",
        "TASK13_PHASE": "development",
        "TASK13_WORKER_NONCE": nonce,
    }
    (out / "output").mkdir()
    mounts = [
        (runtime["source_dir"], "/app/source", True),
        (runtime["dependencies_dir"], "/opt/task13-deps", True),
        (str(spec), "/app/spec.json", True),
        (runtime["import_source_dir"], "/app/import-source", True),
        (str(out / "budget"), "/app/budget", True),
        (str(out / "dispatch"), "/app/import-dispatch", False),
        (str(host._agent), "/app/agent", True),
        (str(out / "output"), "/app/output", False),
    ]
    cmd = [
        "docker",
        "run",
        "--interactive",
        "--name",
        name,
        "--label",
        "task13.free.nonce=" + nonce,
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "2g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
    ]
    for key, value in envs.items():
        cmd += ["--env", key + "=" + value]
    for source, target, readonly in mounts:
        cmd += [
            "--mount",
            "type=bind,source="
            + source
            + ",target="
            + target
            + (",readonly" if readonly else ""),
        ]
    cmd += [
        "--entrypoint",
        "python3",
        runtime["image_id"],
        "-B",
        "-m",
        "scripts.task13_worker_runtime",
    ]
    environment = clean_environment()
    docker = recording_docker(docker_runner(environment), out)
    receipt = {
        "schema_version": "task13-startup-native-verification-v1",
        "status": "failed",
        "started_at": datetime.now(UTC).isoformat(),
        "source_commit": request.source_commit,
        "network": "none",
        "original_account_writes": False,
        "copied_budget_and_journal": True,
        "provider_key_read": False,
        "provider_calls": 0,
        "GO_sent": False,
        "actual_timing_credit": 0,
    }
    process = None
    started = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        line = await asyncio.wait_for(process.stderr.readline(), timeout=120)
        write_raw(out / "probe-stderr-first-line.bin", line)
        elapsed = time.monotonic() - started
        require(
            0 < elapsed < 120 and line.startswith(b"TASK13_WORKER_PROBE:"),
            "full pre-GO probe missing/late",
        )
        probe = json.loads(line.removeprefix(b"TASK13_WORKER_PROBE:"))
        inspected = docker(inspect_arguments(name))
        write_raw(out / "inspection.json", inspected.stdout)
        info = inspection_value(inspected.stdout)
        inspect_container(
            info, name=name, nonce=nonce, runtime=runtime, network="none", mounts=mounts
        )
        config = info["HostConfig"]
        require(
            config["Memory"] == 2147483648
            and config["NanoCpus"] == 2000000000
            and config["PidsLimit"] == 256,
            "native resource boundary differs",
        )
        require(
            probe["pid"] == 1
            and probe["nonce"] == nonce
            and probe["hostname"] == info["Config"]["Hostname"],
            "native process identity differs",
        )
        require(
            all(
                record["readable"] is False
                for records in probe["boundaries"].values()
                for record in records
            ),
            "forbidden boundary readable",
        )
        validate_worker_binding(
            probe, info, nonce=nonce, agent_sha256=request.agent_sha256
        )
        validate_e_planning_probe(
            probe["planning"],
            request,
            authority_sha256=runtime["planning_authority_sha256"],
        )
        receipt.update(
            status="passed",
            probe=probe,
            probe_elapsed_seconds=elapsed,
            container_id=info["Id"],
        )
    finally:
        try:
            receipt["container_absent"] = cleanup_owned(docker, name, nonce)
        finally:
            if process is not None:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=30
                )
                write_raw(out / "stdout.bin", stdout)
                write_raw(out / "stderr-rest.bin", stderr)
            write_json(out / "lifecycle.json", {"events": docker.events})
            write_json(
                out / "process.json",
                {
                    "argv": cmd,
                    "returncode": getattr(process, "returncode", None),
                    "stdin_bytes": 0,
                },
            )
            receipt["finished_at"] = datetime.now(UTC).isoformat()
            receipt["artifacts"] = {
                p.name: pin(p) for p in out.iterdir() if p.is_file()
            }
            write_json(out / "receipt.json", receipt)
    return pin(out / "receipt.json")


PROGRAM = "\nimport json,os,socket\nfrom pathlib import Path\nfrom urllib.parse import urlsplit\nfrom sqlalchemy import create_engine,text\nfrom sqlalchemy.engine import make_url\nimport httpx\nresult={'status':'failed','postgres_select1':False,'opensearch_http_status':None,'provider_keys_present':False,'model_calls':0,'case_database_or_index_created':False,'private_event_queries':0,'queries_read_only':True,'worker_pid':os.getpid(),'worker_nonce':os.environ['TASK13_FREE_NONCE'],'container_hostname':socket.gethostname(),'source_commit':os.environ['SOURCE_COMMIT']}\nengine=None\ntry:\n    assert os.getpid()==1\n    assert 'DEEPSEEK_API_KEY' not in os.environ and 'SSLKEYLOGFILE' not in os.environ\n    assert json.loads(Path('/app/source/source_receipt.json').read_bytes())['source_commit']==os.environ['SOURCE_COMMIT']\n    database=make_url(os.environ['DATABASE_URL'])\n    search=urlsplit(os.environ['OPENSEARCH_URL'])\n    assert database.host=='evidencesoc-postgres-1' and database.port==5432\n    assert not {'host','port','hostaddr','service','servicefile'}.intersection(database.query)\n    assert search.hostname=='evidencesoc-opensearch-1' and search.port==9200\n    assert search.path in {'','/'} and not search.query and not search.fragment\n    engine=create_engine(database,connect_args={'connect_timeout':10})\n    with engine.connect() as connection:\n        connection.execute(text('SET TRANSACTION READ ONLY'))\n        connection.execute(text(\"SET LOCAL statement_timeout = '5000ms'\"))\n        assert connection.execute(text('SELECT 1')).scalar_one()==1\n        result['postgres_select1']=True\n    with httpx.Client(timeout=15,trust_env=False,follow_redirects=False) as client:\n        response=client.get(os.environ['OPENSEARCH_URL'])\n        result['opensearch_http_status']=response.status_code\n        assert response.status_code==200 and isinstance(response.json(),dict)\n    result['status']='verified'\nexcept Exception as error:  # noqa: BLE001 - never expose credentials from subprocess errors\n    result['error_type']=type(error).__name__\nfinally:\n    if engine is not None: engine.dispose()\nprint(json.dumps(result,sort_keys=True))\nraise SystemExit(0 if result['status']=='verified' else 2)\n"


class PriceTable(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows, self.row, self.cell = ([], None, None)

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag in {"td", "th"} and self.row is not None:
            self.cell = ""

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data

    def handle_endtag(self, tag):
        if tag in {"td", "th"} and self.cell is not None:
            self.row.append(re.sub("\\s+", "", self.cell))
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row = None


def check_price_document(html):
    table = PriceTable()
    table.feed(html)
    rates = []
    for row in table.rows:
        if (
            len(row) >= 2
            and re.fullmatch("[0-9.]+元", row[-2])
            and re.fullmatch("[0-9.]+元", row[-1])
        ):
            rates.append((float(row[-2][:-1]), float(row[-1][:-1])))
    require(
        rates == [(0.02, 0.15), (0.04, 0.3), (1, 4.5), (2, 9), (4, 13.5), (8, 27)],
        "official_price_rates_changed",
    )
    require(
        all(
            s in html
            for s in (
                "deepseek-flash",
                "DeepSeek-V4.1-Flash-1017",
                "9:00 - 12:00",
                "14:00 - 18:00",
                "中国法定节假日",
            )
        ),
        "official_model_or_calendar_changed",
    )
    return {
        "offpeak_cache_hit_per_million_cny": 0.02,
        "peak_cache_hit_per_million_cny": 0.04,
        "offpeak_input_per_million_cny": 1,
        "peak_input_per_million_cny": 2,
        "offpeak_output_per_million_cny": 4,
        "peak_output_per_million_cny": 8,
    }


def services_probe(host, request, env_path, out):
    runtime = host._inputs["runtime_options"]
    environment = clean_environment()
    environment.update(service_environment(env_path))
    raw_dir = out / "services-raw"
    raw_dir.mkdir()
    docker = recording_docker(docker_runner(environment), raw_dir)
    nonce = uuid.uuid4().hex
    name = "task13-free-services-" + nonce
    network = runtime["network"]
    inspected = json.loads(docker(["network", "inspect", network]).stdout)[0]
    require(
        inspected["Id"] == runtime["network_id_observed"]
        and {"evidencesoc-postgres-1", "evidencesoc-opensearch-1"}
        <= {v["Name"] for v in inspected["Containers"].values()},
        "service network differs",
    )
    mounts = [
        (runtime["dependencies_dir"], "/opt/task13-deps", True),
        (runtime["source_dir"], "/app/source", True),
    ]
    args = [
        "create",
        "--name",
        name,
        "--label",
        "task13.free.nonce=" + nonce,
        "--read-only",
        "--network",
        network,
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--env",
        "PYTHONPATH=/opt/task13-deps",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "SOURCE_COMMIT=" + request.source_commit,
        "--env",
        "TASK13_FREE_NONCE=" + nonce,
        "--env",
        "DATABASE_URL",
        "--env",
        "OPENSEARCH_URL",
    ]
    for source, target, _ in mounts:
        args += ["--mount", f"type=bind,source={source},target={target},readonly"]
    args += ["--entrypoint", "python3", runtime["image_id"], "-B", "-c", PROGRAM]
    receipt = {
        "schema_version": "task13-e-service-environment-preflight-v1",
        "status": "failed",
        "source_commit": request.source_commit,
        "errors": [],
        "provider_credentials_parsed_or_injected": False,
        "paid_calls": 0,
        "real_plan_approvals": 0,
        "real_timing_credit": 0,
    }
    try:
        container = docker(args).stdout.decode().strip()
        inspected = docker(inspect_arguments(container, service=True))
        info = inspection_value(inspected.stdout, service=True)
        require(info["Id"] == container, "service container ID differs")
        inspect_container(
            info,
            name=name,
            nonce=nonce,
            runtime=runtime,
            network=network,
            mounts=mounts,
        )
        response = docker(["start", "--attach", container], timeout=90, check=False)
        terminal = docker(inspect_arguments(container, service=True))
        state = inspection_value(terminal.stdout, service=True)["State"]
        result = json.loads(response.stdout)
        require(
            response.returncode == 0
            and state["ExitCode"] == 0
            and result["status"] == "verified"
            and result["postgres_select1"] is True
            and result["opensearch_http_status"] == 200
            and result["model_calls"] == 0
            and result["provider_keys_present"] is False,
            "read-only service probe failed",
        )
        receipt.update(result=result, service_checks_passed=True)
    finally:
        try:
            receipt["container_absent"] = cleanup_owned(
                docker, name, nonce, service=True
            )
            if receipt.get("service_checks_passed") is True:
                receipt["status"] = "verified"
        finally:
            receipt["finished_at"] = datetime.now(UTC).isoformat()
            receipt["artifacts"] = {
                "lifecycle.json": write_json(
                    raw_dir / "lifecycle.json", {"events": docker.events}
                )
            }
            receipt["container_name"] = name
            receipt["nonce"] = nonce
            write_json(out / "services.json", receipt)
            environment.clear()
    return pin(out / "services.json")


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PermissionError("public document redirect forbidden")


def public_probe(request, reference, out):
    """Exactly two unauthenticated official GETs. No proxy, cookies or redirects."""
    # Explicit secure client context avoids SSLKEYLOGFILE side effects even for library use.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    retrievals = {}
    documents = {}
    texts = {}
    for name, url in URLS.items():
        started = datetime.now(UTC).isoformat()
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Task13-free-admission/1.0", "Accept": "text/html"},
            method="GET",
        )
        with opener.open(req, timeout=30) as response:
            require(
                response.status == 200 and response.geturl() == url,
                "official response differs",
            )
            raw = response.read(2000001)
            require(len(raw) <= 2000000, "official document exceeds size cap")
        document = raw.decode("utf-8")
        parser = VisibleText()
        parser.feed(document)
        text = "\n".join(p.strip() for p in parser.parts if p.strip())
        documents[name] = document
        texts[name] = text
        retrievals[name] = {
            "official_url": url,
            "response_url": url,
            "http_status": 200,
            "retrieval_started_at_utc": started,
            "retrieved_at_utc": datetime.now(UTC).isoformat(),
            "html": write_raw(out / (name + ".html"), raw),
            "text": write_raw(out / (name + ".txt"), text.encode()),
        }
    model = request.model.model_dump(mode="json")
    rates = check_price_document(documents["official-pricing"])
    require(
        rates == reference["expected_flash_rates_cny_per_million"],
        "frozen prices drifted",
    )
    validate_public_model(documents, texts, model)
    return write_json(
        out / "public.json",
        {
            "schema_version": "task13supplementE-public-freeze-review-v1",
            "checked_at": datetime.now(UTC).isoformat(),
            "source_commit": request.source_commit,
            "status": "public_spec_matches_pending_runtime_check",
            "blockers": [],
            "expected_frozen_model": model,
            "observed_flash_rates_cny_per_million": rates,
            "official_document_get_requests": 2,
            "public_fetches": retrievals,
            "new_paid_calls": 0,
            "provider_chat_completions_requests": 0,
            "model_list_requests": 0,
            "search_or_fetch_api_requests": 0,
            "registrations_by_this_check": 0,
            "credential_or_env_file_reads": False,
            "database_access": False,
        },
    )


def raw_evidence(reference, *, root=None):
    from evals.timing_pool_controller import require_plain_path
    from scripts.task13_e_trial import _read_pin

    path = require_plain_path(reference["path"], file=True)
    if root is not None:
        require(
            path.is_relative_to(Path(root)), "raw admission evidence escaped gate root"
        )
    return _read_pin(reference)


def lifecycle_events(receipt, *, root):
    from scripts.task13_e_trial import _decode

    artifacts = receipt["artifacts"]
    for reference in artifacts.values():
        raw_evidence(reference, root=root)
    events = _decode(raw_evidence(artifacts["lifecycle.json"], root=root))["events"]
    require(isinstance(events, list) and events, "Docker lifecycle evidence missing")
    for event in events:
        require(
            type(event["returncode"]) is int and event["returncode"] == 0,
            "Docker lifecycle command failed",
        )
        event["raw_stdout"] = raw_evidence(event["stdout"], root=root)
        event["raw_stderr"] = raw_evidence(event["stderr"], root=root)
    return events


def validate_cleanup_events(events, info, *, name, nonce, service=False):
    require(len(events) == 3, "complete owned cleanup lifecycle required")
    inspection, removal, absence = events
    require(
        inspection["argv"] == inspect_arguments(name, service=service),
        "cleanup inspection command differs",
    )
    owned = inspection_value(inspection["raw_stdout"], service=service)
    require(
        owned["Id"] == info["Id"]
        and owned["Name"] == "/" + name
        and owned["Config"]["Labels"].get("task13.free.nonce") == nonce
        and owned["Image"] == info["Image"]
        and owned["Config"] == info["Config"]
        and mount_identity(owned) == mount_identity(info),
        "cleanup container identity differs",
    )
    require(
        removal["argv"] == ["rm", "--force", info["Id"]]
        and removal["raw_stdout"].strip() == info["Id"].encode(),
        "owned removal raw evidence differs",
    )
    require(
        absence["argv"]
        == [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            "name=^/" + name + "$",
            "--format",
            "{{.ID}}",
        ]
        and not absence["raw_stdout"].strip(),
        "owned container absence not established",
    )


def validate_native_artifacts(receipt, host, request, *, root):
    from scripts.task13_e_trial import _decode
    from scripts.task13_worker_runtime import (
        validate_e_planning_probe,
        validate_worker_binding,
    )

    artifacts = receipt["artifacts"]
    mandatory = {
        "inspection.json",
        "lifecycle.json",
        "process.json",
        "spec.json",
        "probe-stderr-first-line.bin",
        "stdout.bin",
        "stderr-rest.bin",
    }
    require(mandatory <= set(artifacts), "native raw artifact closure incomplete")
    events = lifecycle_events(receipt, root=root)
    require(len(events) == 4, "native inspect and cleanup lifecycle differs")
    raw = raw_evidence(artifacts["inspection.json"], root=root)
    require(
        events[0]["raw_stdout"] == raw,
        "native inspection summary differs from Docker raw",
    )
    info = inspection_value(raw)
    probe_raw = raw_evidence(artifacts["probe-stderr-first-line.bin"], root=root)
    require(
        probe_raw.startswith(b"TASK13_WORKER_PROBE:"), "native raw probe prefix absent"
    )
    probe = _decode(probe_raw.removeprefix(b"TASK13_WORKER_PROBE:"))
    require(
        probe == receipt["probe"], "native probe summary contradicts raw worker output"
    )
    nonce = probe["nonce"]
    name = "task13-free-startup-" + nonce
    require(re.fullmatch("[a-f0-9]{32}", nonce) is not None, "native nonce malformed")
    require(
        events[0]["argv"] == inspect_arguments(name)
        and receipt["container_id"] == info["Id"],
        "native inspected container differs",
    )
    runtime = host._inputs["runtime_options"]
    out = Path(artifacts["spec.json"]["path"]).parent
    mounts = [
        (runtime["source_dir"], "/app/source", True),
        (runtime["dependencies_dir"], "/opt/task13-deps", True),
        (str(out / "spec.json"), "/app/spec.json", True),
        (runtime["import_source_dir"], "/app/import-source", True),
        (str(out / "budget"), "/app/budget", True),
        (str(out / "dispatch"), "/app/import-dispatch", False),
        (str(host._agent), "/app/agent", True),
        (str(out / "output"), "/app/output", False),
    ]
    inspect_container(
        info, name=name, nonce=nonce, runtime=runtime, network="none", mounts=mounts
    )
    require(
        info["Config"]["Entrypoint"] == ["python3"]
        and info["Config"]["Cmd"] == ["-B", "-m", "scripts.task13_worker_runtime"],
        "native actual entrypoint differs",
    )
    config = info["HostConfig"]
    require(
        config["Memory"] == 2147483648
        and config["NanoCpus"] == 2000000000
        and config["PidsLimit"] == 256,
        "native actual resource limits differ",
    )
    validate_worker_binding(probe, info, nonce=nonce, agent_sha256=request.agent_sha256)
    validate_e_planning_probe(
        probe["planning"],
        request,
        authority_sha256=runtime["planning_authority_sha256"],
    )
    require(
        _decode(raw_evidence(artifacts["spec.json"], root=root))
        == request.model_dump(mode="json"),
        "native raw spec differs from current request",
    )
    process = _decode(raw_evidence(artifacts["process.json"], root=root))
    require(
        process["argv"][:3] == ["docker", "run", "--interactive"]
        and process["argv"][-6:]
        == [
            "--entrypoint",
            "python3",
            runtime["image_id"],
            "-B",
            "-m",
            "scripts.task13_worker_runtime",
        ]
        and process["stdin_bytes"] == 0
        and type(process["returncode"]) is int
        and not raw_evidence(artifacts["stdout.bin"], root=root),
        "native process/no-GO evidence differs",
    )
    validate_cleanup_events(events[1:], info, name=name, nonce=nonce)


def validate_service_artifacts(receipt, host, request, *, root):
    events = lifecycle_events(receipt, root=root)
    require(len(events) == 8, "complete service Docker lifecycle required")
    network, create, initial, start, terminal, *cleanup = events
    runtime = host._inputs["runtime_options"]
    nonce = receipt["nonce"]
    name = "task13-free-services-" + nonce
    require(
        re.fullmatch("[a-f0-9]{32}", nonce) is not None
        and receipt["container_name"] == name,
        "service nonce/name differs",
    )
    require(
        network["argv"] == ["network", "inspect", runtime["network"]],
        "service network command differs",
    )
    network_info = inspection_value(network["raw_stdout"])
    require(
        network_info["Id"] == runtime["network_id_observed"]
        and {"evidencesoc-postgres-1", "evidencesoc-opensearch-1"}
        <= {v["Name"] for v in network_info["Containers"].values()},
        "actual service network differs",
    )
    container = create["raw_stdout"].decode().strip()
    require(
        re.fullmatch("[a-f0-9]{64}", container) is not None,
        "service created ID malformed",
    )
    require(
        initial["argv"] == inspect_arguments(container, service=True)
        and terminal["argv"] == inspect_arguments(container, service=True)
        and start["argv"] == ["start", "--attach", container],
        "service actual lifecycle commands differ",
    )
    info = inspection_value(initial["raw_stdout"], service=True)
    final = inspection_value(terminal["raw_stdout"], service=True)
    mounts = [
        (runtime["dependencies_dir"], "/opt/task13-deps", True),
        (runtime["source_dir"], "/app/source", True),
    ]
    inspect_container(
        info,
        name=name,
        nonce=nonce,
        runtime=runtime,
        network=runtime["network"],
        mounts=mounts,
    )
    require(
        info["Id"] == container
        and final["Id"] == container
        and final["Config"] == info["Config"]
        and mount_identity(final) == mount_identity(info)
        and final["Image"] == info["Image"],
        "service terminal container differs",
    )
    require(
        info["Config"]["Entrypoint"] == ["python3"]
        and info["Config"]["Cmd"] == ["-B", "-c", PROGRAM]
        and {"DATABASE_URL", "OPENSEARCH_URL", "TASK13_FREE_NONCE"}
        <= set(info["Config"]["EnvNames"]),
        "service actual probe command/environment differs",
    )
    require(
        create["argv"][:3] == ["create", "--name", name]
        and create["argv"][-6:]
        == ["--entrypoint", "python3", runtime["image_id"], "-B", "-c", PROGRAM]
        and "TASK13_FREE_NONCE=" + nonce in create["argv"]
        and "SOURCE_COMMIT=" + request.source_commit in create["argv"],
        "service create command differs",
    )
    require(
        final["State"]["ExitCode"] == 0
        and final["State"]["Running"] is False
        and final["State"]["Status"] == "exited",
        "service probe did not exit cleanly",
    )
    result = json.loads(start["raw_stdout"])
    require(result == receipt["result"], "service summary contradicts actual stdout")
    expected = {
        "status": "verified",
        "worker_pid": 1,
        "worker_nonce": nonce,
        "container_hostname": info["Config"]["Hostname"],
        "source_commit": request.source_commit,
        "postgres_select1": True,
        "opensearch_http_status": 200,
        "queries_read_only": True,
        "provider_keys_present": False,
        "model_calls": 0,
        "case_database_or_index_created": False,
        "private_event_queries": 0,
    }
    require(
        all(
            type(result.get(k)) is type(v) and result.get(k) == v
            for k, v in expected.items()
        ),
        "service stdout does not prove bound read-only probe",
    )
    validate_cleanup_events(cleanup, info, name=name, nonce=nonce, service=True)


def validate_public_artifacts(public, reference, request, *, root):
    documents = {}
    texts = {}
    for name, url in URLS.items():
        fetch = public["public_fetches"][name]
        require(
            fetch["official_url"] == url
            and fetch["response_url"] == url
            and fetch["http_status"] == 200,
            "official retrieval identity differs",
        )
        documents[name] = raw_evidence(fetch["html"], root=root).decode("utf-8")
        parser = VisibleText()
        parser.feed(documents[name])
        texts[name] = "\n".join(p.strip() for p in parser.parts if p.strip())
        require(
            raw_evidence(fetch["text"], root=root).decode("utf-8") == texts[name],
            "public extracted text contradicts raw HTML",
        )
    rates = check_price_document(documents["official-pricing"])
    require(
        rates
        == public["observed_flash_rates_cny_per_million"]
        == reference["expected_flash_rates_cny_per_million"],
        "public rate summary contradicts raw pricing table",
    )
    validate_public_model(documents, texts, request.model.model_dump(mode="json"))


def validate_public_model(documents, texts, model):
    table = PriceTable()
    table.feed(documents["official-pricing"])
    models = [r for r in table.rows if r and r[0] == "模型"]
    versions = [r for r in table.rows if r and r[0] == "模型版本"]
    require(
        models
        and model["requested_model"] in models[0][1]
        and versions
        and model["published_version"] == versions[0][1],
        "frozen public model differs",
    )
    require(
        model["thinking"] == "disabled"
        and "思考模式默认打开" in texts["official-thinking-mode"]
        and "thinking" in texts["official-thinking-mode"]
        and "enabled/disabled" in texts["official-thinking-mode"]
        and any(
            r and r[0] == "思考模式" and "非思考" in "".join(r[1:]) for r in table.rows
        ),
        "public thinking mode differs",
    )


def validate_junit_check(check):
    import xml.etree.ElementTree as ET

    raw = raw_evidence(check["junit"])
    require(
        b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(),
        "JUnit entities forbidden",
    )
    try:
        tree = ET.fromstring(raw)
    except ET.ParseError as error:
        raise PermissionError("invalid raw JUnit XML") from error
    require(tree.tag in {"testsuite", "testsuites"}, "JUnit root differs")
    cases = list(tree.iter("testcase"))
    counts = {
        "tests": len(cases),
        "failures": len(list(tree.iter("failure"))),
        "errors": len(list(tree.iter("error"))),
        "skipped": len(list(tree.iter("skipped"))),
    }
    require(
        counts["tests"] > 0
        and all(counts[k] == 0 for k in ("failures", "errors", "skipped")),
        "JUnit raw failures/errors/skips or empty tests",
    )
    for key, value in counts.items():
        require(
            type(check[key]) is int and check[key] == value,
            "JUnit claimed count contradicts raw cases",
        )
    for suite in tree.iter():
        if suite.tag not in {"testsuite", "testsuites"}:
            continue
        actual = {
            "tests": len(list(suite.iter("testcase"))),
            "failures": len(list(suite.iter("failure"))),
            "errors": len(list(suite.iter("error"))),
            "skipped": len(list(suite.iter("skipped"))),
        }
        for key, value in actual.items():
            if suite.tag == "testsuite" or key in suite.attrib:
                require(
                    suite.get(key) is not None
                    and re.fullmatch(r"[0-9]+", suite.get(key))
                    and int(suite.get(key)) == value,
                    "JUnit suite attributes contradict actual nodes",
                )


def select_attempt(controller, trial_id):
    controller.guard()
    state = controller.journal.status()
    require(
        not state["stopped"] and not state["pending"] and state["attempted"] < 6,
        "pool is not ready for a new attempt",
    )
    attempt = controller.pool["attempt_order"][state["attempted"]]
    require(
        attempt["trial_id"] == trial_id, "only the next registered trial may be probed"
    )
    host = controller.hosts[attempt["child_id"]]
    request = next(r for r in host._requests if r.trial_id == trial_id)
    return host, request


def produce(controller, trial_id, service_env):
    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import DEADLINE, require_plain_path
    from scripts.task13_timing_pool import require_free_admission

    host, request = select_attempt(controller, trial_id)
    budget_path = (
        Path(host._inputs["runtime_options"]["budget_dir"]) / "campaign.sqlite"
    )
    require(
        Path(service_env).resolve() == budget_path.resolve().parents[3] / ".env",
        "only original workspace .env service fields are allowed",
    )
    policy = controller.pool["free_admission"]
    require(
        set(policy["helpers"]) == {"assembler", "native_probe", "services"},
        "helper set differs",
    )
    for reference in policy["helpers"].values():
        require(
            reference == pin(__file__)
            and host._timing["source_files"].get(reference["path"])
            == reference["sha256"],
            "this producer must be frozen as all three helpers",
        )
    root = require_plain_path(policy["gate_root"])
    require(root.is_dir(), "approved gate directory missing")
    trial_root = root / trial_id
    trial_root.mkdir(exist_ok=True)
    require_plain_path(trial_root)
    gate_path = trial_root / (uuid.uuid4().hex + ".json")
    # Existing pins are checked before any operation; readers are frozen actual evidence.
    for key in ("reader_regression", "reader_lowlevel", "public_reference"):
        checked(policy[key])
    spent = controller.budget()
    reserve = controller.reserve_bound()
    require(spent + reserve <= 6, "development budget cap")
    out = trial_root / ("artifacts-" + uuid.uuid4().hex)
    out.mkdir()
    native_out = out / "native"
    native_out.mkdir()
    native = asyncio.run(native_probe(host, request, native_out))
    services = services_probe(host, request, service_env, out)
    public = public_probe(request, checked(policy["public_reference"]), out)
    # Check account and next attempt again. Admission never mutates pool/native journals.
    select_attempt(controller, trial_id)
    require(controller.budget() == spent, "budget changed during free admission")
    now = datetime.now(UTC)
    require(now < DEADLINE, "engineering deadline passed")
    state = controller.journal.status()
    review_sha = None
    if state["observed_max_seconds"] > 800:
        from evals.timing_pool_controller import require_current_guard_review

        require_current_guard_review(
            controller.journal._events(),
            canonical_hash(controller.pool),
            now,
            state["observed_max_seconds"],
        )
        review_sha = state["journal_head"]
    gate = {
        "guard_review_sha256": review_sha,
        "schema_version": "task13-host-readonly-paid-dispatch-gate-v1",
        "status": "passed",
        "phase": "pre_plan_no_new_case",
        "pool_registration_sha256": canonical_hash(controller.pool),
        "trial_id": trial_id,
        "planning_request_sha256": canonical_hash(request),
        "source_commit": request.source_commit,
        "ordinal": request.ordinal,
        "host_manifest": host._manifest_pin,
        "provider_requests": 0,
        "plan_approvals": 0,
        "timing_credit": 0,
        "plan_ttl_or_branch_budget_changes": False,
        "automatic_retry": False,
        "actual_new_case_reader_measured": False,
        "actual_six_branch_timing_measured": False,
        "checked_at": now.isoformat(),
        "valid_until": min(now + timedelta(minutes=5), DEADLINE).isoformat(),
        "evidence": {
            "helpers": policy["helpers"],
            "native": native,
            "services": services,
            "public-check": public,
            "reader-regression": policy["reader_regression"],
            "reader-lowlevel": policy["reader_lowlevel"],
        },
        "read_only_budget": {
            "read_only": True,
            "original_budget_identity": request.budget_identity,
            "development_spent_yuan": str(spent),
        },
        "next_three_upper_cny": str(reserve),
    }
    reference = write_json(gate_path, gate)
    require_free_admission(
        reference,
        pool=controller.pool,
        host=host,
        request=request,
        now=datetime.now(UTC),
        spent=spent,
        reserve=reserve,
        guard_review_sha256=review_sha,
    )
    return reference


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--service-env", type=Path, required=True)
    args = parser.parse_args(argv)
    # Drop ambient credentials/proxies before native imports or subprocess creation.
    keep = clean_environment()
    os.environ.clear()
    os.environ.update(keep)
    from scripts.task13_timing_pool import NativePoolController

    try:
        controller = NativePoolController(args.manifest, args.manifest_sha256)
        result = produce(controller, args.trial_id, args.service_env)
    except Exception as error:  # noqa: BLE001 - never expose credentials from subprocess errors
        # Subprocess errors can include service credentials; report only the class.
        print(json.dumps({"status": "STOP", "error_type": type(error).__name__}))
        return 2
    print(
        json.dumps(
            {"status": "passed", "free_admission": result, "provider_requests": 0}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
