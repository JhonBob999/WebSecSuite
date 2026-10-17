"""Only approved, statically identified Nmap can receive fixed local plans."""

from dataclasses import FrozenInstanceError
import hashlib
import importlib
import sys

import pytest

from core.recon.execution_policy import ExecutionPolicy, ExecutionPolicyError, ScopeApproval, preflight_scope
from core.recon.observations import ObservationImportError


def api():
    return importlib.import_module("core.recon.nmap_adapter")


@pytest.fixture
def candidate(monkeypatch, tmp_path):
    module = api()
    if sys.platform != "win32":
        from contextlib import nullcontext
        from core.recon import windows_process
        # These offline adapter fixtures never execute. Production approval
        # still requires the native Windows identity and containment gates.
        monkeypatch.setattr(windows_process, "locked_executable", lambda path: nullcontext())
    path = tmp_path / "nmap.exe"
    image = bytearray(128)
    image[:2] = b"MZ"
    image[60:64] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    path.write_bytes(image)
    monkeypatch.setattr(module, "_inspect_native_identity", lambda value: "7.95")
    monkeypatch.setattr(module, "_process_safety", lambda: (True, "Contained"))
    return module.approve_nmap_path(str(path), confirmed=True)


def version_result(stdout=b"Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64-pc-windows\n", **changes):
    from core.recon.process_supervisor import JobSnapshot, JobState
    fields = dict(job_id="version-job", adapter_id="nmap.version-check", state=JobState.SUCCEEDED,
                  stdout=stdout, stderr=b"", exit_code=0)
    fields.update(changes)
    return JobSnapshot(**fields)


def test_unapproved_path_and_native_program_without_nmap_identity_never_receive_probe(tmp_path):
    module = api()
    with pytest.raises(ExecutionPolicyError):
        module.approve_nmap_path(sys.executable, confirmed=False)
    with pytest.raises(ExecutionPolicyError):
        module.approve_nmap_path(sys.executable, confirmed=True)
    with pytest.raises(ExecutionPolicyError):
        module.prepare_nmap_version_check({"executable_path": sys.executable})
    with pytest.raises(TypeError):
        module.ValidatedNmapTool()


@pytest.mark.parametrize("path", ["nmap.exe", "", "\\\\host\\share\\nmap.exe", "C:\\nmap.exe:stream"])
def test_missing_relative_remote_or_device_path_cannot_be_approved(path):
    with pytest.raises(ExecutionPolicyError):
        api().approve_nmap_path(path, confirmed=True)


def test_approved_candidate_has_only_bounded_version_probe(candidate):
    spec = api().prepare_nmap_version_check(candidate)
    assert spec._plan.arguments == ("--version",)
    assert spec._plan.targets == ()
    assert spec._plan.timeout_ms == 5000
    ExecutionPolicy().validate(spec)
    with pytest.raises(FrozenInstanceError):
        candidate.executable_path = sys.executable


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows executable-image sharing lock")
@pytest.mark.parametrize("operation", ["write", "replace"])
def test_static_approval_holds_one_image_lock_across_identity_and_digest_reads(candidate, monkeypatch, tmp_path, operation):
    from pathlib import Path
    module = api()
    path = Path(candidate.executable_path)
    original = path.read_bytes()
    replacement = tmp_path / "replacement.exe"
    replacement.write_bytes(b"MZ unverified replacement, never launched")

    def inspect_identity(value):
        assert value == str(path)
        with pytest.raises(OSError):
            if operation == "write":
                path.write_bytes(b"MZ unverified replacement, never launched")
            else:
                replacement.replace(path)
        return "7.95"

    monkeypatch.setattr(module, "_inspect_native_identity", inspect_identity)
    approved = module.approve_nmap_path(str(path), confirmed=True)
    assert approved.sha256 == hashlib.sha256(original).hexdigest()
    assert path.read_bytes() == original
    # The temporary lock is released after approval.
    path.write_bytes(original)


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows executable-image sharing lock")
def test_static_approval_rejects_file_already_open_for_writing(candidate):
    from pathlib import Path
    with Path(candidate.executable_path).open("r+b"):
        with pytest.raises(ExecutionPolicyError, match="locked for safe identity verification"):
            api().approve_nmap_path(candidate.executable_path, confirmed=True)


def test_native_resource_identity_rejects_an_actual_different_windows_executable():
    if sys.platform != "win32":
        pytest.skip("Native Windows version-resource inspection")
    with pytest.raises(ExecutionPolicyError):
        api()._inspect_native_identity(sys.executable)


@pytest.mark.parametrize("changed", [{"ProductName": "Other"}, {"InternalName": "cmd"},
    {"FileDescription": "Not Nmap"}, {"OriginalFilename": "python.exe"},
    {"CompanyName": "Unknown"}, {"FileVersion": "7.95 --help"}])
def test_untrusted_static_identity_cannot_reach_a_probe(monkeypatch, changed):
    module = api()
    fields = dict(ProductName="Nmap", InternalName="Nmap", FileDescription="Nmap", OriginalFilename="nmap.exe",
                  CompanyName="Insecure.Org", FileVersion="7.95")
    fields.update(changed)
    monkeypatch.setattr(module, "_read_version_resources", lambda path: fields)
    monkeypatch.setattr(module, "_trusted_publisher", lambda path: "Nmap Software LLC")
    with pytest.raises(ExecutionPolicyError):
        module._inspect_native_identity("nmap.exe")


def test_valid_resources_still_require_a_trusted_signature_publisher(monkeypatch):
    module = api()
    monkeypatch.setattr(module, "_read_version_resources", lambda path: dict(
        ProductName="Nmap", InternalName="Nmap", FileDescription="Nmap", OriginalFilename="nmap.exe",
        CompanyName="Insecure.Org", FileVersion="7.95"))
    monkeypatch.setattr(module, "_trusted_publisher", lambda path: "Unknown Publisher")
    with pytest.raises(ExecutionPolicyError):
        module._inspect_native_identity("nmap.exe")


@pytest.mark.parametrize("changes", [
    {"stdout": b"some other tool version 7.95"}, {"stdout": b"Nmap version 7.94 ( https://nmap.org )\n"},
    {"stdout_truncated": True}, {"stderr_truncated": True}, {"exit_code": 1},
    {"adapter_id": "other"},
])
def test_version_verification_rejects_mismatch_failed_or_truncated_result(candidate, changes):
    with pytest.raises(ExecutionPolicyError):
        api().verify_nmap_version(candidate, version_result(**changes))


def test_fixed_profile_requires_verified_tool_and_fresh_per_run_confirmation(candidate):
    module = api()
    with pytest.raises(ExecutionPolicyError):
        module.prepare_nmap_self_test(candidate, confirmed=True)
    tool = module.verify_nmap_version(candidate, version_result())
    assert tool.version == "7.95"
    with pytest.raises(ExecutionPolicyError):
        module.prepare_nmap_self_test(tool, confirmed=False)
    spec = module.prepare_nmap_self_test(tool, confirmed=True)
    assert spec._plan.arguments == (
        "-sT", "-Pn", "-n", "-p", "80,443,8080,8443", "--max-retries", "1",
        "--max-rate", "10", "--host-timeout", "30s", "--no-stylesheet", "-oX", "-", "127.0.0.1",
    )
    assert spec._plan.targets == ("127.0.0.1",)
    assert spec._plan.timeout_ms == 40000
    policy = ExecutionPolicy()
    policy._claim(spec)
    with pytest.raises(ExecutionPolicyError):
        policy._claim(spec)
    # Reusing a confirmation to prepare a second spec is rejected too.
    with pytest.raises(ExecutionPolicyError):
        policy.prepare("nmap.local-self-test", module._SelfTestRequest(tool), spec._approval)
    assert not preflight_scope(("127.0.0.1",), spec._approval).allowed
    assert not preflight_scope(("127.0.0.1",), ScopeApproval(exact_domains=("example.com",))).allowed


@pytest.mark.parametrize("target", ["localhost", "::1", "127.0.0.2", "example.com", "127.0.0.1/32", "127.0.0.1 --script all", ("127.0.0.1",)])
def test_local_confirmation_never_grants_other_target_identity(candidate, target):
    tool = api().verify_nmap_version(candidate, version_result())
    with pytest.raises(ExecutionPolicyError):
        api().prepare_nmap_self_test(tool, confirmed=True, target=target)


def test_containment_gate_or_changed_file_revokes_already_prepared_spec(candidate, monkeypatch):
    module = api()
    tool = module.verify_nmap_version(candidate, version_result())
    spec = module.prepare_nmap_self_test(tool, confirmed=True)
    monkeypatch.setattr(module, "_process_safety", lambda: (False, "Unavailable"))
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)
    monkeypatch.setattr(module, "_process_safety", lambda: (True, "Contained"))
    from pathlib import Path
    Path(candidate.executable_path).write_bytes(b"MZ replacement")
    with pytest.raises(ExecutionPolicyError):
        ExecutionPolicy().validate(spec)


def xml_report(doctype=b"<!DOCTYPE nmaprun>", *, state=b"open", address=b"127.0.0.1", port=b"80", finished=b'success'):
    return (b'<?xml version="1.0" encoding="UTF-8"?>\n' + doctype + b'\n'
            b'<nmaprun scanner="nmap" version="7.95"><scaninfo type="connect" protocol="tcp" '
            b'numservices="4" services="80,443,8080,8443"/><host><status state="up"/>'
            b'<address addr="' + address + b'" addrtype="ipv4"/><ports><port protocol="tcp" portid="' + port +
            b'"><state state="' + state + b'"/><service name="http" method="table" conf="3"/></port>'
            b'<extraports state="closed" count="3"/></ports>'
            b'</host><runstats><finished exit="' + finished + b'" time="1"/><hosts up="1" down="0" total="1"/>'
            b'</runstats></nmaprun>')


def test_known_doctype_is_accepted_only_in_trusted_output_and_keeps_original_digest():
    from core.recon.nmap_import import parse_nmap_xml
    raw = xml_report()
    with pytest.raises(ObservationImportError):
        parse_nmap_xml(raw)
    batch = api().parse_trusted_nmap_output(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert batch.run_id == "nmap:sha256:" + digest
    assert [(item.entity_type, item.value, item.port) for item in batch.observations] == [
        ("ip", "127.0.0.1", None), ("service", "127.0.0.1", 80),
    ]
    for item in batch.observations:
        evidence = next(value for value in item.evidence if value.kind == "nmap-run")
        assert evidence.metadata["file_sha256"] == digest
        assert evidence.metadata["file_size"] == len(raw)
        assert evidence.metadata["doctype_normalized"] is True


@pytest.mark.parametrize("doctype", [
    b'<!DOCTYPE nmaprun SYSTEM "https://evil.test/a.dtd">', b'<!DOCTYPE nmaprun PUBLIC "x" "y">',
    b'<!DOCTYPE nmaprun [<!ENTITY x "boom">]>', b'<!DOCTYPE nmaprun []>',
    b'<!DOCTYPE  nmaprun>', b'<!DOCTYPE nmaprun >', b'<!DOCTYPE other>',
    b'<!DOCTYPE nmaprun>\n<!DOCTYPE nmaprun>',
])
def test_live_xml_rejects_every_other_doctype_form(doctype):
    with pytest.raises(ObservationImportError):
        api().parse_trusted_nmap_output(xml_report(doctype))


@pytest.mark.parametrize("changes", [{"address": b"192.0.2.1"}, {"port": b"22"}, {"finished": b"error"}])
def test_unexpected_target_port_or_unsuccessful_report_is_never_importable(changes):
    with pytest.raises(ObservationImportError):
        api().parse_trusted_nmap_output(xml_report(**changes))


def test_complete_zero_open_report_is_valid_but_truncated_report_is_rejected():
    batch = api().parse_trusted_nmap_output(xml_report(state=b"closed"))
    assert [item.entity_type for item in batch.observations] == ["ip"]
    with pytest.raises(ObservationImportError):
        api().parse_trusted_nmap_output(xml_report()[:-20])


@pytest.mark.parametrize("source", [
    xml_report(b"").replace(b"<host>", b"<host><![CDATA[<!DOCTYPE nmaprun>]]>"),
    xml_report(b"<!-- <!DOCTYPE nmaprun> -->"),
    xml_report(b"").replace(b"</nmaprun>", b"<!DOCTYPE nmaprun></nmaprun>"),
])
def test_doctype_normalization_never_removes_a_comment_cdata_or_late_declaration(source):
    with pytest.raises(ObservationImportError):
        api().parse_trusted_nmap_output(source)


@pytest.mark.parametrize("content", [
    xml_report().replace(b'<scaninfo type="connect"', b'<scaninfo type="syn"'),
    xml_report().replace(b'<finished exit="success" time="1"/>', b""),
    xml_report().replace(b'<finished exit="success" time="1"/>', b'<finished exit="success"/><finished exit="success"/>'),
    xml_report().replace(b'<address addr="127.0.0.1" addrtype="ipv4"/>', b'<address addr="127.0.0.1" addrtype="ipv4"/><address addr="192.0.2.1" addrtype="ipv4"/>'),
    xml_report().replace(b'</ports>', b'</ports><hostnames><hostname name="example.com"/></hostnames>'),
    xml_report().replace(b'<port protocol="tcp"', b'<port protocol="udp"'),
])
def test_unexpected_or_incomplete_local_report_cannot_supply_observations(content):
    with pytest.raises(ObservationImportError):
        api().parse_trusted_nmap_output(content)


@pytest.mark.parametrize("content", [
    xml_report().replace(b"<host>", b'<host timedout="true">'),
    xml_report().replace(b'<status state="up"/>', b'<status state="down"/>'),
    xml_report().replace(b'<extraports state="closed" count="3"/>', b""),
    xml_report().replace(b'<extraports state="closed" count="3"/>', b'<extraports state="closed" count="4"/>'),
    xml_report().replace(b'<extraports state="closed" count="3"/>', b'<extraports state="open" count="3"/>'),
    xml_report().replace(b'<state state="open"/>', b""),
    xml_report().replace(b'<hosts up="1" down="0" total="1"/>', b'<hosts up="0" down="0" total="0"/>'),
    xml_report().replace(b'<scaninfo type="connect" protocol="tcp" numservices="4" services="80,443,8080,8443"/>', b""),
    xml_report().replace(b'</ports>', b'<port protocol="tcp" portid="80"><state state="closed"/></port></ports>'),
])
def test_host_timeout_or_missing_port_accounting_cannot_look_like_success(content):
    with pytest.raises(ObservationImportError):
        api().parse_trusted_nmap_output(content)
