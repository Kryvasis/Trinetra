"""Transient SSH/HTTP configuration collection for the Cortex bridge."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from io import StringIO
from urllib.parse import urljoin, urlsplit

import requests


MAX_CONFIG_BYTES = 1024 * 1024
SSH_TIMEOUT = 15
HTTP_TIMEOUT = 15
MAX_REDIRECTS = 3
VENDOR_COMMANDS = {
    "cisco": "show running-config",
    "juniper": "show configuration | display set",
    "generic": "show running-config",
}
HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")


class LiveFetchError(RuntimeError):
    """A collection failure safe for the bridge to translate generically."""


def get_vendor_command(vendor: str | None) -> str:
    key = (vendor or "auto").strip().lower()
    return VENDOR_COMMANDS.get(key, VENDOR_COMMANDS["generic"])


def _read_private_key(paramiko, key_text: str, passphrase: str | None):
    value = key_text.strip()
    if "PRIVATE KEY" not in value or "\n" not in value:
        raise ValueError("ssh_key must contain PEM private-key data; server file paths are not accepted")

    key_classes = [
        getattr(paramiko, name, None)
        for name in ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey")
    ]
    for key_class in filter(None, key_classes):
        try:
            return key_class.from_private_key(StringIO(value), password=passphrase or None)
        except Exception:
            continue
    raise ValueError("unable to parse SSH private key")


def fetch_via_ssh(
    host: str,
    username: str,
    password: str | None = None,
    ssh_key: str | None = None,
    vendor: str = "auto",
    port: int = 22,
    timeout: int = SSH_TIMEOUT,
    vendor_command: str | None = None,
) -> str:
    if not isinstance(host, str) or not host.strip():
        raise ValueError("SSH target host is required")
    if not isinstance(username, str) or not username.strip():
        raise ValueError("SSH username is required")
    if not password and not ssh_key:
        raise ValueError("SSH requires a password or private key")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")

    try:
        import paramiko
    except ImportError as exc:
        raise LiveFetchError("SSH collection support is unavailable") from exc

    pkey = _read_private_key(paramiko, ssh_key, password) if ssh_key else None
    command = vendor_command.strip() if vendor_command and vendor_command.strip() else get_vendor_command(vendor)
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    connect_args = {
        "hostname": host.strip(),
        "port": port,
        "username": username.strip(),
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if pkey is not None:
        connect_args["pkey"] = pkey
    else:
        connect_args["password"] = password

    try:
        client.connect(**connect_args)
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        raw = stdout.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise LiveFetchError("collected configuration exceeds the 1 MB limit")
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0 and not raw.strip():
            stderr.read(512)
            raise LiveFetchError("the remote configuration command failed")
        text = raw.decode("utf-8", errors="replace")
        if not text.strip():
            raise LiveFetchError("the remote configuration command returned no data")
        return text
    except (ValueError, LiveFetchError):
        raise
    except Exception as exc:
        raise LiveFetchError("SSH collection failed") from exc
    finally:
        client.close()


def _private_urls_allowed() -> bool:
    return os.getenv("TRINETRA_LIVE_FETCH_ALLOW_PRIVATE_URLS", "").lower() in {"1", "true", "yes"}


def _validate_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL target is required")
    value = url.strip()
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must use http:// or https:// and include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials must not be embedded in the URL")

    if not _private_urls_allowed():
        try:
            addresses = {
                item[4][0]
                for item in socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)
            }
        except socket.gaierror as exc:
            raise LiveFetchError("the URL hostname could not be resolved") from exc
        if not addresses:
            raise LiveFetchError("the URL hostname could not be resolved")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ValueError("URL targets must resolve to public network addresses")
    return value


def fetch_via_url(
    url: str,
    auth_token: str | None = None,
    auth_header: str | None = None,
    timeout: int = HTTP_TIMEOUT,
) -> str:
    current_url = _validate_url(url)
    header_name = (auth_header or "Authorization").strip()
    if not HEADER_NAME_RE.fullmatch(header_name):
        raise ValueError("invalid authentication header name")

    headers = {
        "Accept": "text/plain, application/json, application/xml;q=0.9, */*;q=0.5",
        "User-Agent": "Cortex-Bridge/1.0",
    }
    if auth_token:
        token = auth_token.strip()
        headers[header_name] = f"Bearer {token}" if header_name.lower() == "authorization" and " " not in token else token

    session = requests.Session()
    session.trust_env = False
    try:
        for redirect_count in range(MAX_REDIRECTS + 1):
            response = session.get(current_url, headers=headers, timeout=timeout, stream=True, allow_redirects=False)
            try:
                if response.is_redirect or response.is_permanent_redirect:
                    if redirect_count == MAX_REDIRECTS:
                        raise LiveFetchError("too many URL redirects")
                    location = response.headers.get("Location")
                    if not location:
                        raise LiveFetchError("URL redirect did not include a destination")
                    previous = urlsplit(current_url)
                    next_url = _validate_url(urljoin(current_url, location))
                    destination = urlsplit(next_url)
                    if previous.scheme.lower() == "https" and destination.scheme.lower() != "https":
                        raise ValueError("HTTPS collection cannot redirect to an insecure URL")
                    if (previous.hostname, previous.port) != (destination.hostname, destination.port):
                        headers.pop(header_name, None)
                    current_url = next_url
                    continue

                response.raise_for_status()
                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > MAX_CONFIG_BYTES:
                            raise LiveFetchError("collected configuration exceeds the 1 MB limit")
                    except ValueError:
                        pass
                body = bytearray()
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    body.extend(chunk)
                    if len(body) > MAX_CONFIG_BYTES:
                        raise LiveFetchError("collected configuration exceeds the 1 MB limit")
                text = bytes(body).decode(response.encoding or "utf-8", errors="replace")
                if not text.strip():
                    raise LiveFetchError("the URL returned no configuration data")
                return text
            finally:
                response.close()
    except (ValueError, LiveFetchError):
        raise
    except requests.RequestException as exc:
        raise LiveFetchError("URL collection failed") from exc
    finally:
        session.close()

    raise LiveFetchError("URL collection failed")


def fetch_config(
    source_type: str,
    target: str,
    vendor: str = "auto",
    username: str | None = None,
    password: str | None = None,
    ssh_key: str | None = None,
    auth_token: str | None = None,
    auth_header: str | None = None,
    port: int = 22,
    vendor_command: str | None = None,
    timeout: int | None = None,
) -> str:
    source = source_type.strip().lower() if isinstance(source_type, str) else ""
    if source == "ip":
        return fetch_via_ssh(
            target, username, password, ssh_key, vendor, port,
            timeout or SSH_TIMEOUT, vendor_command,
        )
    if source == "url":
        return fetch_via_url(target, auth_token, auth_header, timeout or HTTP_TIMEOUT)
    raise ValueError("source_type must be 'ip' or 'url'")
