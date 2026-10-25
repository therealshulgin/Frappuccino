#!/usr/bin/env python3
"""
The QUIC front must keep no access log.

The relay keeps no trace of the requests it carries: nginx runs with
`access_log off` and uvicorn with `--no-access-log`. The QUIC front (Caddy,
deploy/caddy/Caddyfile) is the third component on the request path, and Caddy
writes an access log as soon as a site block holds a `log` directive. An
earlier, unversioned copy of that file had one. These checks read the
versioned file and the script that runs it, and the kernel UDP buffers the
front and the de-obfuscation proxy depend on (deploy/sysctl/).
"""

import re
from pathlib import Path

DEPLOY = Path(__file__).resolve().parent.parent / "deploy" / "caddy"
CADDYFILE = DEPLOY / "Caddyfile"
RUN_SCRIPT = DEPLOY / "run-quic-front.sh"

_LOG_DIRECTIVE = re.compile(r"^\s*log(\s|\{|$)")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _directives(text: str) -> list[str]:
    """The lines of a Caddyfile with comments removed."""
    lines = []
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        if code.strip():
            lines.append(code)
    return lines


def _has_log_directive(text: str) -> bool:
    return any(_LOG_DIRECTIVE.match(line) for line in _directives(text))


def test_the_caddyfile_has_no_log_directive():
    assert not _has_log_directive(CADDYFILE.read_text(encoding="utf-8"))


def test_the_check_sees_a_log_directive_when_there_is_one():
    # Negative control: the same check on the earlier shape of the file.
    earlier = ":8444 {\n\tlog {\n\t\toutput stdout\n\t}\n\treverse_proxy 127.0.0.1:8000\n}\n"
    assert _has_log_directive(earlier)
    assert not _has_log_directive("# log {\n:8444 {\n\treverse_proxy 127.0.0.1:8000\n}\n")


def test_the_front_proxies_to_the_relay_on_loopback():
    text = "\n".join(_directives(CADDYFILE.read_text(encoding="utf-8")))
    assert re.search(r"reverse_proxy\s+127\.0\.0\.1:8000\b", text)
    assert "tls /certs/frappuccino_ca.crt /certs/frappuccino_ca.key" in text


def test_the_published_caddyfile_names_no_host_address():
    # The file is public: no address other than loopback belongs in it.
    addresses = set(_IPV4.findall(CADDYFILE.read_text(encoding="utf-8")))
    assert addresses <= {"127.0.0.1"}


def test_the_run_script_pins_the_image_and_caps_the_container_log():
    script = RUN_SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"IMAGE='caddy@sha256:[0-9a-f]{64}'", script)
    assert "--log-opt max-size=" in script
    assert "--log-opt max-file=" in script
    assert "/etc/caddy/Caddyfile:ro" in script


def test_the_run_script_refuses_a_caddyfile_that_logs():
    # The script carries its own guard, for a file edited on the host.
    script = RUN_SCRIPT.read_text(encoding="utf-8")
    assert "refusing to start a front that logs requests" in script


SYSCTL = DEPLOY.parent / "sysctl" / "90-frappuccino-udp.conf"
# quic-go's recommendation for its receive and send buffers.
_QUIC_GO_BUFFER = 7_500_000


def _sysctl_values(text: str) -> dict[str, int]:
    values = {}
    for line in _directives(text):
        key, _, value = line.partition("=")
        values[key.strip()] = int(value.strip())
    return values


def test_the_udp_buffers_let_quic_go_have_what_it_asks_for():
    values = _sysctl_values(SYSCTL.read_text(encoding="utf-8"))
    assert values["net.core.rmem_max"] >= _QUIC_GO_BUFFER
    assert values["net.core.wmem_max"] >= _QUIC_GO_BUFFER
    # The de-obfuscation proxy asks for no size: it gets the default, which
    # must be well above Ubuntu's 212992.
    assert values["net.core.rmem_default"] > 212_992
    assert values["net.core.rmem_default"] <= values["net.core.rmem_max"]
