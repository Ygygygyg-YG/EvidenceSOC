import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[2] / "scripts/task13_pool_admission.py"


def helper():
    assert PATH.exists(), "free admission producer is missing"
    spec = importlib.util.spec_from_file_location("admission", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_environment_never_inherits_provider_keys():
    m = helper()
    assert m.clean_environment(
        {"PATH": "bin", "DEEPSEEK_API_KEY": "secret", "HTTP_PROXY": "private"}
    ) == {"PATH": "bin"}


def test_selected_service_values_do_not_parse_provider_or_interpolate(tmp_path):
    m = helper()
    path = tmp_path / ".env"
    path.write_text(
        "DEEPSEEK_API_KEY=secret\nDATABASE_URL=postgresql://u:p@localhost/db\nOPENSEARCH_URL=http://localhost:9201\n"
    )
    result = m.service_environment(path)
    assert set(result) == {"DATABASE_URL", "OPENSEARCH_URL"}
    assert "evidencesoc-postgres-1" in result["DATABASE_URL"]
    assert result["OPENSEARCH_URL"] == "http://evidencesoc-opensearch-1:9200"


@pytest.mark.parametrize(
    "line",
    [
        "DATABASE_URL=postgresql://u:p@remote/db",
        "DATABASE_URL=postgresql://u:p@localhost/db?host=remote",
    ],
)
def test_service_endpoint_override_rejected(tmp_path, line):
    m = helper()
    path = tmp_path / ".env"
    path.write_text(line + "\nOPENSEARCH_URL=http://localhost:9201\n")
    with pytest.raises((ValueError, PermissionError)):
        m.service_environment(path)


def test_exclusive_receipt_and_hash_check(tmp_path):
    m = helper()
    path = tmp_path / "receipt.json"
    pin = m.write_json(path, {"status": "measured"})
    assert m.checked(pin) == {"status": "measured"}
    with pytest.raises(FileExistsError):
        m.write_json(path, {})
    path.write_text("{}")
    with pytest.raises(PermissionError):
        m.checked(pin)


def test_owned_cleanup_rejects_foreign_nonce():
    m = helper()
    calls = []

    def docker(args, **kwargs):
        calls.append(args)
        import json
        from types import SimpleNamespace

        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "Id": "a" * 64,
                        "Name": "/expected",
                        "Config": {"Labels": {"task13.free.nonce": "foreign"}},
                    }
                ]
            ).encode(),
        )

    with pytest.raises(PermissionError):
        m.cleanup_owned(docker, "expected", "nonce")
    assert all("rm" not in call for call in calls)


def test_only_next_unclaimed_trial_is_selected():
    from types import SimpleNamespace

    m = helper()
    state = {"stopped": None, "pending": None, "attempted": 0}
    request = SimpleNamespace(trial_id="next")
    host = SimpleNamespace(_requests=[request])
    controller = SimpleNamespace(
        guard=lambda: None,
        journal=SimpleNamespace(status=lambda: state),
        pool={"attempt_order": [{"trial_id": "next", "child_id": "a"}]},
        hosts={"a": host},
    )
    assert m.select_attempt(controller, "next") == (host, request)
    with pytest.raises(PermissionError):
        m.select_attempt(controller, "wrong")
    state["pending"] = "next"
    with pytest.raises(PermissionError):
        m.select_attempt(controller, "next")


def test_native_probe_real_validators_and_owned_cleanup(tmp_path, monkeypatch):
    import asyncio
    import json
    import sqlite3
    from types import SimpleNamespace

    from evals.contracts import canonical_hash
    from evals.e_planning import planning_requests
    from evals.tests.test_e_timing_replicates import registration
    from scripts import task13_worker_runtime as runtime_module

    m = helper()
    (tmp_path / "fixture").mkdir()
    request = planning_requests(
        registration(tmp_path / "fixture")["planning_registration"]
    )[0]
    agent = tmp_path / "agent"
    agent.mkdir()
    (agent / "events.jsonl").write_bytes(b"events")
    request = request.model_copy(
        update={"agent_sha256": m.sha256(b"events").hexdigest()}
    )
    budget = tmp_path / "budget"
    budget.mkdir()
    journal = tmp_path / "e-planning.sqlite"
    for path in (budget / "campaign.sqlite", journal):
        with sqlite3.connect(path) as con:
            con.execute("create table marker(x)")
    deps = tmp_path / "deps"
    deps.mkdir()
    (deps / "task13_dependencies.json").write_text("{}")
    runtime = {
        "budget_dir": str(budget),
        "dependencies_dir": str(deps),
        "source_dir": str(tmp_path / "source"),
        "import_source_dir": str(tmp_path / "import"),
        "planning_authority_sha256": "a" * 64,
        "image_id": "sha256:" + "b" * 64,
    }
    host = SimpleNamespace(
        _agent=agent,
        _inputs={
            "runtime_options": runtime,
            "planning_authority": {"journal_path": str(journal)},
        },
    )
    monkeypatch.setattr(runtime_module, "e_planning_runtime_binding", lambda *args: {})
    import itertools

    ticks = itertools.count(1)
    monkeypatch.setattr(m, "time", SimpleNamespace(monotonic=lambda: next(ticks) / 10))
    info = {}
    commands = []
    sent = []
    removed = []

    async def create(*args, **kwargs):
        commands.extend(args)
        forbidden_argument = next(
            argument
            for argument in args
            if argument.startswith("TASK13_FORBIDDEN_PATHS=")
        )
        forbidden_paths = json.loads(forbidden_argument.split("=", 1)[1])
        assert all("\\" not in paths[0] for paths in forbidden_paths.values()), (
            "Windows host canaries must be segmented POSIX paths in Linux; otherwise long COW paths exceed NAME_MAX"
        )
        assert all(
            len(component.encode("utf-8")) <= 255
            for paths in forbidden_paths.values()
            for path in paths
            for component in path.split("/")
        )
        assert kwargs["env"].keys() <= {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "COMSPEC",
            "PATHEXT",
        }
        name = args[args.index("--name") + 1]
        label = args[args.index("--label") + 1]
        nonce = label.split("=", 1)[1]
        mounts = []
        for index, arg in enumerate(args):
            if arg == "--mount":
                parts = args[index + 1].split(",")
                values = dict(p.split("=", 1) for p in parts if "=" in p)
                mounts.append(
                    {
                        "Type": "bind",
                        "Source": values["source"],
                        "Destination": values["target"],
                        "RW": "readonly" not in parts,
                    }
                )
        info.update(
            Name="/" + name,
            Id="c" * 64,
            Image=runtime["image_id"],
            Config={
                "Labels": {"task13.free.nonce": nonce},
                "Image": runtime["image_id"],
                "User": "65532:65532",
                "Hostname": "c" * 12,
                "Env": [],
                "Entrypoint": ["python3"],
                "Cmd": ["-B", "-m", "scripts.task13_worker_runtime"],
            },
            HostConfig={
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 2147483648,
                "NanoCpus": 2000000000,
                "PidsLimit": 256,
            },
            Mounts=mounts,
            State={"Running": True},
        )
        probe = {
            "pid": 1,
            "nonce": nonce,
            "hostname": "c" * 12,
            "agent_readable": True,
            "agent_sha256": request.agent_sha256,
            "boundaries": {
                k: [{"readable": False}] for k in ("scoring", "git", "other_case")
            },
            "forbidden_reads": [{"readable": False}],
            "planning": {
                "source_package_manifest_sha256": request.source_package_manifest_sha256,
                "registration_sha256": request.registration_sha256,
                "request_sha256": canonical_hash(request),
                "authority_sha256": "a" * 64,
                "readonly_source": True,
                "writable_dispatch": True,
            },
        }

        async def readline():
            return b"TASK13_WORKER_PROBE:" + json.dumps(probe).encode() + b"\n"

        async def communicate(*args):
            sent.extend(args)
            return b"", b""

        return SimpleNamespace(
            stderr=SimpleNamespace(readline=readline),
            communicate=communicate,
            returncode=137,
        )

    def docker(args, **kwargs):
        if args[0] == "inspect":
            return SimpleNamespace(returncode=0, stdout=json.dumps([info]).encode())
        if args[0] == "rm":
            removed.append(args[-1])
            return SimpleNamespace(returncode=0, stdout=(args[-1] + "\n").encode())
        return SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(m, "docker_runner", lambda env: docker)
    out = tmp_path / "output"
    out.mkdir()
    result = m.checked(asyncio.run(m.native_probe(host, request, out)))
    assert result["status"] == "passed" and result["container_absent"] is True
    assert removed == ["c" * 64] and sent == []
    assert "--network" in commands and "none" in commands
    assert result["artifacts"]["inspection.json"]["sha256"]
    m.validate_native_artifacts(result, host, request, root=tmp_path)
    from copy import deepcopy

    changed = deepcopy(result)
    changed["probe"]["pid"] = 2
    with pytest.raises(PermissionError):
        m.validate_native_artifacts(changed, host, request, root=tmp_path)
    # Real native validator rejects a forged request hash and finally still removes only owned ID.
    request = request.model_copy(update={"agent_sha256": request.agent_sha256})
    original = runtime_module.validate_e_planning_probe

    def reject(probe, request, **kwargs):
        probe["request_sha256"] = "f" * 64
        original(probe, request, **kwargs)

    monkeypatch.setattr(runtime_module, "validate_e_planning_probe", reject)
    failed = tmp_path / "failed"
    failed.mkdir()
    with pytest.raises(ValueError):
        asyncio.run(m.native_probe(host, request, failed))
    assert removed == ["c" * 64, "c" * 64]
    assert m.checked(m.pin(failed / "receipt.json"))["status"] == "failed"


@pytest.mark.parametrize("shared_max", [384, 900])
def test_producer_gate_accepted_by_real_controller_and_rejects_drift(
    tmp_path, monkeypatch, shared_max
):
    from datetime import UTC, datetime, timedelta
    from decimal import Decimal
    from types import SimpleNamespace

    from evals.e_planning import planning_requests
    from evals.tests.test_e_timing_replicates import registration
    from scripts.task13_timing_pool import require_free_admission

    m = helper()
    now = datetime.now(UTC)
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    request = planning_requests(registration(fixture)["planning_registration"])[0]
    request = request.model_copy(
        update={
            "model": request.model.model_copy(
                update={
                    "requested_model": "deepseek-flash",
                    "published_version": "DeepSeek-V4.1-Flash-1017",
                    "thinking": "disabled",
                }
            )
        }
    )
    root = tmp_path / "gates"
    root.mkdir()
    helper_pin = m.pin(PATH)
    junit = m.write_raw(
        tmp_path / "results.xml",
        b'<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="ok"/></testsuite>',
    )
    check = {"tests": 1, "failures": 0, "errors": 0, "skipped": 0, "junit": junit}
    regression = m.write_json(
        tmp_path / "readers.json",
        {"tests": {"regression": check, "final-neighbor": check}},
    )
    lowlevel = m.write_json(
        tmp_path / "lowlevel.json",
        {
            "status": "passed",
            "diagnostic_only": True,
            "live_state_equals_retained": True,
            "new_provider_calls": 0,
            "new_plan_approvals": 0,
            "new_timing_credit": 0,
            "host_read_receipt": {
                "checkpoint_transaction_read_only": "on",
                "business_transaction_read_only": "on",
            },
        },
    )
    public_reference = m.write_json(
        tmp_path / "public-ref.json",
        {"expected_flash_rates_cny_per_million": expected_rates()},
    )
    policy = {
        "gate_root": str(root),
        "helpers": dict.fromkeys(("assembler", "native_probe", "services"), helper_pin),
        "reader_regression": regression,
        "reader_lowlevel": lowlevel,
        "public_reference": public_reference,
    }
    host = SimpleNamespace(
        _requests=[request],
        _agent=tmp_path / "agent",
        _manifest_pin={"path": "host", "sha256": "a" * 64},
        _timing={"source_files": {helper_pin["path"]: helper_pin["sha256"]}},
        _inputs={
            "runtime_options": {
                "planning_authority_sha256": "a" * 64,
                "budget_dir": str(tmp_path / "data/task13/budget"),
                "source_dir": str(tmp_path / "source"),
                "dependencies_dir": str(tmp_path / "deps"),
                "import_source_dir": str(tmp_path / "import"),
                "image_id": "sha256:" + "b" * 64,
                "network": "local-services",
                "network_id_observed": "d" * 64,
            }
        },
    )
    controller = SimpleNamespace(
        guard=lambda: None,
        journal=SimpleNamespace(
            status=lambda: {"stopped": None, "pending": None, "attempted": 0}
        ),
        pool={
            "free_admission": policy,
            "attempt_order": [{"trial_id": request.trial_id, "child_id": "a"}],
        },
        hosts={"a": host},
        budget=lambda: Decimal(1),
        reserve_bound=lambda: Decimal(".5"),
    )

    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import GUARD_FORMULA, PoolJournal

    controller.journal = PoolJournal.prepare(
        tmp_path / "pool-journal.jsonl",
        pool_sha256=canonical_hash(controller.pool),
        attempts=[request.trial_id] + [f"future{i}" for i in range(5)],
        imported_trial_id="old",
        now=now,
        imported_max_seconds=shared_max,
    )
    review_sha = None
    if shared_max > 800:
        with controller.journal.lock():
            controller.journal._append(
                "guard_review",
                {
                    "schema_version": "task13-pool-guard-review-v1",
                    "pool_registration_sha256": canonical_hash(controller.pool),
                    "journal_head_sha256": controller.journal.status()["journal_head"],
                    "checked_at": now.isoformat(),
                    "formula_version": GUARD_FORMULA,
                    "observations": [
                        {
                            "trial_id": "old",
                            "duration_wall_seconds": shared_max,
                            "duration_monotonic_seconds": shared_max,
                        }
                    ],
                    "settlement_evidence_sha256": [],
                    "observed_max_seconds": shared_max,
                },
                controller.journal._events(),
            )
        review_sha = controller.journal.status()["journal_head"]

    async def native(host, request, out):
        return native_raw_fixture(m, host, request, out)

    def services(host, request, env, out):
        return service_raw_fixture(m, host, request, out)

    def public(request, reference, out):
        return public_raw_fixture(m, request, out)

    monkeypatch.setattr(m, "native_probe", native)
    monkeypatch.setattr(m, "services_probe", services)
    monkeypatch.setattr(m, "public_probe", public)
    reference = m.produce(controller, request.trial_id, tmp_path / ".env")
    args = {
        "pool": controller.pool,
        "host": host,
        "request": request,
        "now": datetime.now(UTC),
        "spent": Decimal(1),
        "reserve": Decimal(".5"),
        "guard_review_sha256": review_sha,
    }
    assert m.checked(reference).get("guard_review_sha256") == review_sha
    assert require_free_admission(reference, **args)["sha256"] == reference["sha256"]
    from evals.timing_pool_evidence import validate_phase_free_admission

    recorded = require_free_admission(reference, **args)
    validate_phase_free_admission(recorded, **args)
    with pytest.raises(PermissionError):
        validate_phase_free_admission(
            {**recorded, "checked_at": "2026-01-01T00:00:00+00:00"}, **args
        )
    second = m.produce(controller, request.trial_id, tmp_path / ".env")
    assert second["path"] != reference["path"] and Path(reference["path"]).exists()
    with pytest.raises(PermissionError):
        require_free_admission(reference, **{**args, "now": now + timedelta(minutes=6)})
    with pytest.raises(PermissionError):
        require_free_admission(
            reference,
            **{**args, "request": request.model_copy(update={"trial_id": "wrong"})},
        )
    gate = m.checked(reference)
    gate["schema_version"] = "invented"
    bad = m.write_json(Path(reference["path"]).parent / ("f" * 32 + ".json"), gate)
    with pytest.raises(PermissionError):
        require_free_admission(bad, **args)
    Path(reference["path"]).write_text("{}")
    with pytest.raises(PermissionError):
        require_free_admission(reference, **args)


@pytest.mark.parametrize("drift", [False, True])
def test_public_fetch_two_exact_gets_and_price_drift(tmp_path, monkeypatch, drift):
    from types import SimpleNamespace

    m = helper()
    pricing = "<table><tr><td>模型</td><td>deepseek-flash</td></tr><tr><td>模型版本</td><td>DeepSeek-V4.1-Flash-1017</td></tr><tr><td>思考模式</td><td>非思考</td></tr>"
    for first, second in [
        ("0.02", "0.15"),
        ("0.04", "0.30"),
        ("1", "4.5"),
        ("2", "9"),
        ("4", "13.5"),
        ("8", "27"),
    ]:
        if drift and first == "8":
            first = "9"
        pricing += f"<tr><td>{first}元</td><td>{second}元</td></tr>"
    pricing += "</table>9:00 - 12:00 14:00 - 18:00 中国法定节假日"
    seen = []

    class Response:
        status = 200

        def __init__(self, url):
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def geturl(self):
            return self.url

        def read(self, limit):
            return (
                pricing
                if self.url == m.URLS["official-pricing"]
                else "思考模式默认打开 thinking enabled/disabled"
            ).encode()

    class Opener:
        def open(self, request, timeout):
            assert request.method == "GET" and request.data is None
            assert not {"authorization", "cookie"} & {
                key.lower() for key in request.headers
            }
            seen.append(request.full_url)
            return Response(request.full_url)

    monkeypatch.setattr(m.urllib.request, "build_opener", lambda *args: Opener())
    model = {
        "requested_model": "deepseek-flash",
        "published_version": "DeepSeek-V4.1-Flash-1017",
        "thinking": "disabled",
    }
    request = SimpleNamespace(
        model=SimpleNamespace(model_dump=lambda **kwargs: model), source_commit="a" * 40
    )
    reference = {
        "expected_flash_rates_cny_per_million": {
            "offpeak_cache_hit_per_million_cny": 0.02,
            "peak_cache_hit_per_million_cny": 0.04,
            "offpeak_input_per_million_cny": 1,
            "peak_input_per_million_cny": 2,
            "offpeak_output_per_million_cny": 4,
            "peak_output_per_million_cny": 8,
        }
    }
    if drift:
        with pytest.raises(PermissionError):
            m.public_probe(request, reference, tmp_path)
        assert not (tmp_path / "public.json").exists()
    else:
        result = m.checked(m.public_probe(request, reference, tmp_path))
        assert result["expected_frozen_model"] == model
        assert result["official_document_get_requests"] == 2
        for value in result["public_fetches"].values():
            assert m.pin(value["html"]["path"]) == value["html"]
    assert seen == list(m.URLS.values())


@pytest.mark.parametrize(
    "xml,claimed",
    [
        (
            '<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="ok"/></testsuite>',
            1,
        ),
        (
            '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="ok"/></testsuite></testsuites>',
            1,
        ),
    ],
)
def test_junit_counts_derive_from_actual_nodes(tmp_path, xml, claimed):
    m = helper()
    assert hasattr(m, "validate_junit_check"), "raw JUnit closure missing"
    check = {
        "tests": claimed,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "junit": m.write_raw(tmp_path / "junit.xml", xml.encode()),
    }
    m.validate_junit_check(check)


@pytest.mark.parametrize(
    "xml",
    [
        '<testsuite tests="1" failures="0" errors="0" skipped="0"/>',
        '<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase><failure/></testcase></testsuite>',
        '<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase><error/></testcase></testsuite>',
        '<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase><skipped/></testcase></testsuite>',
        '<testsuite tests="2" failures="0" errors="0" skipped="0"><testcase/></testsuite>',
        "<unrelated><testcase/></unrelated>",
    ],
)
def test_junit_resigned_summary_cannot_hide_missing_or_failed_nodes(tmp_path, xml):
    m = helper()
    assert hasattr(m, "validate_junit_check"), "raw JUnit closure missing"
    check = {
        "tests": 1,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "junit": m.write_raw(tmp_path / "junit.xml", xml.encode()),
    }
    with pytest.raises((ValueError, PermissionError)):
        m.validate_junit_check(check)


def test_missing_native_and_service_raw_artifacts_rejected(tmp_path):
    m = helper()
    assert hasattr(m, "validate_native_artifacts"), "raw native closure missing"
    assert hasattr(m, "validate_service_artifacts"), "raw service closure missing"
    for validator in (m.validate_native_artifacts, m.validate_service_artifacts):
        with pytest.raises((ValueError, PermissionError, KeyError)):
            validator({"status": "passed"}, None, None, root=tmp_path)


def expected_rates():
    return {
        "offpeak_cache_hit_per_million_cny": 0.02,
        "peak_cache_hit_per_million_cny": 0.04,
        "offpeak_input_per_million_cny": 1,
        "peak_input_per_million_cny": 2,
        "offpeak_output_per_million_cny": 4,
        "peak_output_per_million_cny": 8,
    }


def public_raw_fixture(m, request, out):
    from datetime import UTC, datetime

    pricing = "<table><tr><td>模型</td><td>deepseek-flash</td></tr><tr><td>模型版本</td><td>DeepSeek-V4.1-Flash-1017</td></tr><tr><td>思考模式</td><td>非思考</td></tr>"
    for first, second in [
        ("0.02", "0.15"),
        ("0.04", "0.30"),
        ("1", "4.5"),
        ("2", "9"),
        ("4", "13.5"),
        ("8", "27"),
    ]:
        pricing += f"<tr><td>{first}元</td><td>{second}元</td></tr>"
    pricing += "</table>9:00 - 12:00 14:00 - 18:00 中国法定节假日"
    fetches = {}
    for name, url in m.URLS.items():
        html = (
            pricing
            if name == "official-pricing"
            else "思考模式默认打开 thinking enabled/disabled"
        )
        parser = m.VisibleText()
        parser.feed(html)
        text = "\n".join(p.strip() for p in parser.parts if p.strip())
        fetches[name] = {
            "official_url": url,
            "response_url": url,
            "http_status": 200,
            "html": m.write_raw(out / (name + ".html"), html.encode()),
            "text": m.write_raw(out / (name + ".txt"), text.encode()),
        }
    return m.write_json(
        out / "public.json",
        {
            "status": "public_spec_matches_pending_runtime_check",
            "blockers": [],
            "expected_frozen_model": request.model.model_dump(mode="json"),
            "observed_flash_rates_cny_per_million": expected_rates(),
            "official_document_get_requests": 2,
            "new_paid_calls": 0,
            "provider_chat_completions_requests": 0,
            "model_list_requests": 0,
            "search_or_fetch_api_requests": 0,
            "registrations_by_this_check": 0,
            "credential_or_env_file_reads": False,
            "database_access": False,
            "checked_at": datetime.now(UTC).isoformat(),
            "public_fetches": fetches,
        },
    )


def raw_event(m, out, index, argv, value):
    import json
    from datetime import UTC, datetime

    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return {
        "argv": argv,
        "returncode": 0,
        "recorded_at": datetime.now(UTC).isoformat(),
        "stdout": m.write_raw(out / f"{index}.out", raw),
        "stderr": m.write_raw(out / f"{index}.err", b""),
    }


def fixture_inspection(host, name, nonce, mounts, service=False):
    runtime = host._inputs["runtime_options"]
    return {
        "Name": "/" + name,
        "Id": "c" * 64,
        "Image": runtime["image_id"],
        "Config": {
            "Labels": {"task13.free.nonce": nonce},
            "Image": runtime["image_id"],
            "User": "65532:65532",
            "Hostname": "c" * 12,
            "Entrypoint": ["python3"],
            "Cmd": [],
            "EnvNames": ["DATABASE_URL", "OPENSEARCH_URL", "TASK13_FREE_NONCE"]
            if service
            else [],
        },
        "HostConfig": {
            "NetworkMode": runtime["network"] if service else "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "Memory": 2147483648,
            "NanoCpus": 2000000000,
            "PidsLimit": 256,
        },
        "Mounts": [
            {"Type": "bind", "Source": str(source), "Destination": target, "RW": not ro}
            for source, target, ro in mounts
        ],
        "State": {
            "Running": not service,
            "ExitCode": 0,
            "Status": "exited" if service else "running",
        },
    }


def cleanup_raw_events(m, out, start, info, name, nonce, service=False):
    container = info["Id"]
    return [
        raw_event(
            m,
            out,
            start,
            m.inspect_arguments(name, service=service),
            info if service else [info],
        ),
        raw_event(
            m, out, start + 1, ["rm", "--force", container], (container + "\n").encode()
        ),
        raw_event(
            m,
            out,
            start + 2,
            [
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                "name=^/" + name + "$",
                "--format",
                "{{.ID}}",
            ],
            b"",
        ),
    ]


def native_raw_fixture(m, host, request, out):
    import json
    from datetime import UTC, datetime

    from evals.contracts import canonical_hash

    runtime = host._inputs["runtime_options"]
    nonce = "a" * 32
    name = "task13-free-startup-" + nonce
    mounts = [
        (runtime["source_dir"], "/app/source", True),
        (runtime["dependencies_dir"], "/opt/task13-deps", True),
        (out / "spec.json", "/app/spec.json", True),
        (runtime["import_source_dir"], "/app/import-source", True),
        (out / "budget", "/app/budget", True),
        (out / "dispatch", "/app/import-dispatch", False),
        (host._agent, "/app/agent", True),
        (out / "output", "/app/output", False),
    ]
    info = fixture_inspection(host, name, nonce, mounts)
    info["Config"]["Cmd"] = ["-B", "-m", "scripts.task13_worker_runtime"]
    probe = {
        "pid": 1,
        "nonce": nonce,
        "hostname": "c" * 12,
        "agent_readable": True,
        "agent_sha256": request.agent_sha256,
        "boundaries": {
            k: [{"readable": False}] for k in ("scoring", "git", "other_case")
        },
        "forbidden_reads": [{"readable": False}],
        "planning": {
            "source_package_manifest_sha256": request.source_package_manifest_sha256,
            "registration_sha256": request.registration_sha256,
            "request_sha256": canonical_hash(request),
            "authority_sha256": runtime["planning_authority_sha256"],
            "readonly_source": True,
            "writable_dispatch": True,
        },
    }
    events = [
        raw_event(m, out, 0, m.inspect_arguments(name), [info]),
        *cleanup_raw_events(m, out, 1, info, name, nonce),
    ]
    artifacts = {
        "inspection.json": events[0]["stdout"],
        "probe-stderr-first-line.bin": m.write_raw(
            out / "probe.bin", b"TASK13_WORKER_PROBE:" + json.dumps(probe).encode()
        ),
        "spec.json": m.write_json(out / "spec.json", request.model_dump(mode="json")),
        "stdout.bin": m.write_raw(out / "stdout.bin", b""),
        "stderr-rest.bin": m.write_raw(out / "stderr-rest.bin", b""),
        "process.json": m.write_json(
            out / "process.json",
            {
                "argv": [
                    "docker",
                    "run",
                    "--interactive",
                    "--entrypoint",
                    "python3",
                    runtime["image_id"],
                    "-B",
                    "-m",
                    "scripts.task13_worker_runtime",
                ],
                "returncode": 137,
                "stdin_bytes": 0,
            },
        ),
        "lifecycle.json": m.write_json(out / "lifecycle.json", {"events": events}),
    }
    return m.write_json(
        out / "native.json",
        {
            "schema_version": "task13-startup-native-verification-v1",
            "status": "passed",
            "source_commit": request.source_commit,
            "network": "none",
            "original_account_writes": False,
            "copied_budget_and_journal": True,
            "provider_key_read": False,
            "provider_calls": 0,
            "GO_sent": False,
            "actual_timing_credit": 0,
            "container_absent": True,
            "probe_elapsed_seconds": 1,
            "finished_at": datetime.now(UTC).isoformat(),
            "container_id": info["Id"],
            "probe": probe,
            "artifacts": artifacts,
        },
    )


def service_raw_fixture(m, host, request, out):
    from datetime import UTC, datetime

    runtime = host._inputs["runtime_options"]
    nonce = "b" * 32
    name = "task13-free-services-" + nonce
    raw = out / "service"
    raw.mkdir()
    mounts = [
        (runtime["source_dir"], "/app/source", True),
        (runtime["dependencies_dir"], "/opt/task13-deps", True),
    ]
    info = fixture_inspection(host, name, nonce, mounts, service=True)
    info["Config"]["Cmd"] = ["-B", "-c", m.PROGRAM]
    result = {
        "status": "verified",
        "worker_pid": 1,
        "worker_nonce": nonce,
        "container_hostname": "c" * 12,
        "source_commit": request.source_commit,
        "postgres_select1": True,
        "opensearch_http_status": 200,
        "queries_read_only": True,
        "provider_keys_present": False,
        "model_calls": 0,
        "case_database_or_index_created": False,
        "private_event_queries": 0,
    }
    args = [
        "create",
        "--name",
        name,
        "--env",
        "TASK13_FREE_NONCE=" + nonce,
        "--env",
        "SOURCE_COMMIT=" + request.source_commit,
        "--entrypoint",
        "python3",
        runtime["image_id"],
        "-B",
        "-c",
        m.PROGRAM,
    ]
    network = {
        "Id": runtime["network_id_observed"],
        "Containers": {
            "pg": {"Name": "evidencesoc-postgres-1"},
            "os": {"Name": "evidencesoc-opensearch-1"},
        },
    }
    events = [
        raw_event(m, raw, 0, ["network", "inspect", runtime["network"]], [network]),
        raw_event(m, raw, 1, args, (info["Id"] + "\n").encode()),
        raw_event(m, raw, 2, m.inspect_arguments(info["Id"], service=True), info),
        raw_event(m, raw, 3, ["start", "--attach", info["Id"]], result),
        raw_event(m, raw, 4, m.inspect_arguments(info["Id"], service=True), info),
        *cleanup_raw_events(m, raw, 5, info, name, nonce, service=True),
    ]
    return m.write_json(
        out / "services.json",
        {
            "schema_version": "task13-e-service-environment-preflight-v1",
            "status": "verified",
            "source_commit": request.source_commit,
            "service_checks_passed": True,
            "container_absent": True,
            "errors": [],
            "provider_credentials_parsed_or_injected": False,
            "paid_calls": 0,
            "real_plan_approvals": 0,
            "real_timing_credit": 0,
            "finished_at": datetime.now(UTC).isoformat(),
            "nonce": nonce,
            "container_name": name,
            "result": result,
            "artifacts": {
                "lifecycle.json": m.write_json(
                    raw / "lifecycle.json", {"events": events}
                )
            },
        },
    )


def fixture_free_policy(root, tree):
    """TEST ONLY: offline files for a compiled synthetic/COW pool's admission policy."""
    from scripts import task13_pool_admission as m

    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    code = m.pin(Path(tree) / "scripts/task13_pool_admission.py")
    junit = m.write_raw(
        root / "fixture-reader-junit.xml",
        b'<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="offline-reader-fixture"/></testsuite>',
    )
    check = {"tests": 1, "failures": 0, "errors": 0, "skipped": 0, "junit": junit}
    return {
        "gate_root": str(root),
        "helpers": dict.fromkeys(("assembler", "native_probe", "services"), code),
        "reader_regression": m.write_json(
            root / "fixture-readers.json",
            {"tests": {"regression": check, "final-neighbor": check}},
        ),
        "reader_lowlevel": m.write_json(
            root / "fixture-lowlevel.json",
            {
                "status": "passed",
                "diagnostic_only": True,
                "live_state_equals_retained": True,
                "new_provider_calls": 0,
                "new_plan_approvals": 0,
                "new_timing_credit": 0,
                "host_read_receipt": {
                    "checkpoint_transaction_read_only": "on",
                    "business_transaction_read_only": "on",
                },
            },
        ),
        "public_reference": m.write_json(
            root / "fixture-public-reference.json",
            {"expected_flash_rates_cny_per_million": expected_rates()},
        ),
    }


def build_fixture_admission(controller, request, root):
    """TEST ONLY: replace producer external I/O, retain real producer and all validators.

    This writes synthetic Docker/HTTP/JUnit evidence under the test-owned root.
    It is deliberately outside the production CLI; never use as live admission.
    """
    import importlib.util
    import uuid

    reference = controller.pool["free_admission"]["helpers"]["assembler"]
    spec = importlib.util.spec_from_file_location(
        "fixture_admission_" + uuid.uuid4().hex, reference["path"]
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    from unittest.mock import patch

    assert Path(controller.pool["free_admission"]["gate_root"]).is_relative_to(
        Path(root).resolve()
    )
    host = next(
        h
        for h in controller.hosts.values()
        if any(r.trial_id == request.trial_id for r in h._requests)
    )

    async def native(host, request, out):
        return native_raw_fixture(m, host, request, out)

    def service(host, request, env, out):
        return service_raw_fixture(m, host, request, out)

    def public(request, reference, out):
        return public_raw_fixture(m, request, out)

    env = (
        Path(host._inputs["runtime_options"]["budget_dir"]) / "campaign.sqlite"
    ).resolve().parents[3] / ".env"
    with (
        patch.object(m, "native_probe", native),
        patch.object(m, "services_probe", service),
        patch.object(m, "public_probe", public),
    ):
        return m.produce(controller, request.trial_id, env)


def test_services_producer_retains_raw_lifecycle_without_credentials(
    tmp_path, monkeypatch
):
    import json
    from copy import deepcopy
    from types import SimpleNamespace

    m = helper()
    env = tmp_path / ".env"
    env.write_text(
        "DATABASE_URL=postgresql://localuser:private-password@localhost/db\nOPENSEARCH_URL=http://localhost:9201\nDEEPSEEK_API_KEY=must-not-read-or-save\n"
    )
    runtime = {
        "source_dir": str(tmp_path / "source"),
        "dependencies_dir": str(tmp_path / "deps"),
        "image_id": "sha256:" + "b" * 64,
        "network": "local",
        "network_id_observed": "d" * 64,
    }
    host = SimpleNamespace(_inputs={"runtime_options": runtime})
    request = SimpleNamespace(source_commit="e" * 40)
    info = {}
    result = {}
    seen = []

    def docker(args, **kwargs):
        seen.append(args)
        value = b""
        if args[:2] == ["network", "inspect"]:
            value = json.dumps(
                [
                    {
                        "Id": "d" * 64,
                        "Containers": {
                            "a": {"Name": "evidencesoc-postgres-1"},
                            "b": {"Name": "evidencesoc-opensearch-1"},
                        },
                    }
                ]
            ).encode()
        elif args[0] == "create":
            name = args[2]
            nonce = name.rsplit("-", 1)[1]
            mounts = [
                (runtime["source_dir"], "/app/source", True),
                (runtime["dependencies_dir"], "/opt/task13-deps", True),
            ]
            info.update(fixture_inspection(host, name, nonce, mounts, service=True))
            info["State"] = {"Running": False, "Status": "created", "ExitCode": 0}
            info["Config"]["Cmd"] = ["-B", "-c", m.PROGRAM]
            result.update(
                status="verified",
                worker_pid=1,
                worker_nonce=nonce,
                container_hostname="c" * 12,
                source_commit=request.source_commit,
                postgres_select1=True,
                opensearch_http_status=200,
                queries_read_only=True,
                provider_keys_present=False,
                model_calls=0,
                case_database_or_index_created=False,
                private_event_queries=0,
            )
            value = ("c" * 64 + "\n").encode()
        elif args[0] == "inspect":
            assert args[-2:] == ["--format", m.SERVICE_INSPECT_TEMPLATE]
            value = json.dumps(info).encode()
        elif args[0] == "start":
            info["State"] = {"Running": False, "Status": "exited", "ExitCode": 0}
            value = json.dumps(result).encode()
        elif args[0] == "rm":
            value = ("c" * 64 + "\n").encode()
        return SimpleNamespace(returncode=0, stdout=value, stderr=b"")

    monkeypatch.setattr(m, "docker_runner", lambda environment: docker)
    receipt = m.checked(m.services_probe(host, request, env, tmp_path))
    m.validate_service_artifacts(receipt, host, request, root=tmp_path)
    assert len(seen) == 8
    for path in (tmp_path / "services-raw").iterdir():
        assert (
            b"private-password" not in path.read_bytes()
            and b"must-not-read-or-save" not in path.read_bytes()
        )
    changed = deepcopy(receipt)
    changed["result"]["postgres_select1"] = False
    with pytest.raises(PermissionError):
        m.validate_service_artifacts(changed, host, request, root=tmp_path)


@pytest.mark.parametrize(
    "attack",
    [
        "probe_summary",
        "native_image",
        "native_missing",
        "native_cleanup",
        "service_summary",
        "service_exit",
        "service_entrypoint",
        "service_cleanup",
        "public_rate",
        "public_text",
        "public_model",
    ],
)
def test_resigned_evidence_cannot_contradict_raw_artifacts(tmp_path, attack):
    import uuid
    from types import SimpleNamespace

    from evals.e_planning import planning_requests
    from evals.tests.test_e_timing_replicates import registration

    m = helper()
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    request = planning_requests(registration(fixture)["planning_registration"])[0]
    request = request.model_copy(
        update={
            "model": request.model.model_copy(
                update={
                    "requested_model": "deepseek-flash",
                    "published_version": "DeepSeek-V4.1-Flash-1017",
                    "thinking": "disabled",
                }
            )
        }
    )
    runtime = {
        "source_dir": str(tmp_path / "source"),
        "dependencies_dir": str(tmp_path / "deps"),
        "import_source_dir": str(tmp_path / "import"),
        "image_id": "sha256:" + "b" * 64,
        "network": "local",
        "network_id_observed": "d" * 64,
        "planning_authority_sha256": "a" * 64,
    }
    host = SimpleNamespace(
        _agent=tmp_path / "agent", _inputs={"runtime_options": runtime}
    )
    out = tmp_path / "out"
    out.mkdir()

    def resign(value):
        return m.write_json(out / (uuid.uuid4().hex + ".json"), value)

    if attack.startswith("native") or attack == "probe_summary":
        receipt = m.checked(native_raw_fixture(m, host, request, out))
        if attack == "probe_summary":
            receipt["probe"]["agent_sha256"] = "f" * 64
        elif attack == "native_missing":
            del receipt["artifacts"]["probe-stderr-first-line.bin"]
        elif attack == "native_image":
            value = m.checked(receipt["artifacts"]["inspection.json"])
            value[0]["Image"] = "sha256:" + "f" * 64
            receipt["artifacts"]["inspection.json"] = resign(value)
            lifecycle = m.checked(receipt["artifacts"]["lifecycle.json"])
            lifecycle["events"][0]["stdout"] = receipt["artifacts"]["inspection.json"]
            receipt["artifacts"]["lifecycle.json"] = resign(lifecycle)
        else:
            lifecycle = m.checked(receipt["artifacts"]["lifecycle.json"])
            lifecycle["events"][-1]["stdout"] = m.write_raw(
                out / "not-absent.bin", b"c" * 64
            )
            receipt["artifacts"]["lifecycle.json"] = resign(lifecycle)
        validator = lambda: m.validate_native_artifacts(
            m.checked(resign(receipt)), host, request, root=tmp_path
        )
    elif attack.startswith("service"):
        receipt = m.checked(service_raw_fixture(m, host, request, out))
        if attack == "service_summary":
            receipt["result"]["worker_nonce"] = "f" * 32
        else:
            lifecycle = m.checked(receipt["artifacts"]["lifecycle.json"])
            if attack == "service_cleanup":
                lifecycle["events"][-2]["argv"][-1] = "f" * 64
            else:
                index = 4 if attack == "service_exit" else 2
                value = m.checked(lifecycle["events"][index]["stdout"])
                if attack == "service_exit":
                    value["State"]["ExitCode"] = 7
                else:
                    value["Config"]["Cmd"] = ["-c", "print(True)"]
                lifecycle["events"][index]["stdout"] = resign(value)
            receipt["artifacts"]["lifecycle.json"] = resign(lifecycle)
        validator = lambda: m.validate_service_artifacts(
            m.checked(resign(receipt)), host, request, root=tmp_path
        )
    else:
        public = m.checked(public_raw_fixture(m, request, out))
        if attack == "public_rate":
            public["observed_flash_rates_cny_per_million"][
                "peak_input_per_million_cny"
            ] = 999
        elif attack == "public_text":
            public["public_fetches"]["official-pricing"]["text"] = m.write_raw(
                out / "false.txt", b"false summary"
            )
        else:
            ref = public["public_fetches"]["official-pricing"]
            html = (
                Path(ref["html"]["path"])
                .read_text("utf-8")
                .replace("<td>deepseek-flash</td>", "<td>different-model</td>")
            )
            ref["html"] = m.write_raw(out / "changed.html", html.encode())
            parser = m.VisibleText()
            parser.feed(html)
            ref["text"] = m.write_raw(
                out / "changed.txt",
                "\n".join(p.strip() for p in parser.parts if p.strip()).encode(),
            )
        validator = lambda: m.validate_public_artifacts(
            m.checked(resign(public)),
            {"expected_flash_rates_cny_per_million": expected_rates()},
            request,
            root=tmp_path,
        )
    with pytest.raises((PermissionError, ValueError, KeyError)):
        validator()


def test_container_inspection_rejects_extra_nonbind_mount(tmp_path):
    from types import SimpleNamespace

    m = helper()
    runtime = {
        "source_dir": str(tmp_path),
        "dependencies_dir": str(tmp_path),
        "image_id": "sha256:" + "b" * 64,
        "network": "none",
    }
    host = SimpleNamespace(_inputs={"runtime_options": runtime})
    mounts = [(tmp_path, "/app/source", True)]
    info = fixture_inspection(host, "owned", "a" * 32, mounts)
    info["Mounts"].append(
        {
            "Type": "volume",
            "Destination": "/private",
            "Source": "unapproved",
            "RW": True,
        }
    )
    with pytest.raises(PermissionError):
        m.inspect_container(
            info,
            name="owned",
            nonce="a" * 32,
            runtime=runtime,
            network="none",
            mounts=mounts,
        )


@pytest.mark.parametrize("kind", ["native", "service"])
def test_docker_mount_order_does_not_change_identity(tmp_path, kind):
    import uuid
    from types import SimpleNamespace

    from evals.e_planning import planning_requests
    from evals.tests.test_e_timing_replicates import registration

    m = helper()
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    request = planning_requests(registration(fixture)["planning_registration"])[0]
    host = SimpleNamespace(
        _agent=tmp_path / "agent",
        _inputs={
            "runtime_options": {
                "source_dir": str(tmp_path / "source"),
                "dependencies_dir": str(tmp_path / "deps"),
                "import_source_dir": str(tmp_path / "import"),
                "image_id": "sha256:" + "b" * 64,
                "network": "local",
                "network_id_observed": "d" * 64,
                "planning_authority_sha256": "a" * 64,
            }
        },
    )
    out = tmp_path / "raw"
    out.mkdir()
    producer = native_raw_fixture if kind == "native" else service_raw_fixture
    receipt = m.checked(producer(m, host, request, out))
    lifecycle = m.checked(receipt["artifacts"]["lifecycle.json"])
    indices = [1] if kind == "native" else [4, 5]
    for index in indices:
        value = m.checked(lifecycle["events"][index]["stdout"])
        info = value[0] if kind == "native" else value
        info["Mounts"] = list(reversed(info["Mounts"]))
        lifecycle["events"][index]["stdout"] = m.write_json(
            out / (uuid.uuid4().hex + ".json"), value
        )
    receipt["artifacts"]["lifecycle.json"] = m.write_json(
        out / "reordered-lifecycle.json", lifecycle
    )
    validator = (
        m.validate_native_artifacts
        if kind == "native"
        else m.validate_service_artifacts
    )
    validator(receipt, host, request, root=tmp_path)


def test_mount_identity_rejects_duplicate_destination():
    m = helper()
    record = {
        "Destination": "/app/source",
        "Type": "bind",
        "RW": False,
        "Source": "same",
    }
    with pytest.raises(PermissionError, match="duplicate"):
        m.mount_identity({"Mounts": [record, dict(record)]})
