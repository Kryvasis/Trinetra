"""
TrinetraLiveFetcher — thin retrieval layer for auto-sourced config ingestion.

Purpose: Fetch raw device configuration text from an IP/hostname (via SSH)
or a URL (via HTTP GET) and return it as a plain string. This module does
NO parsing, NO interpretation, NO scoring — its sole job is to produce a
config-text string that is then fed into the exact same ingestion pipeline
(TrinetraConfigIngestor.ingest) as file uploads.

Separation rationale: Python bridge layer was chosen over a Java module
so that fetch logic is cleanly isolated from the ingestion/parsing core
(Java).  The bridge already depends on paramiko + requests for operational
tooling, so no new Java dependencies are introduced, and credential handling
remains confined to the short-lived Python request scope (never persisted to
disk, never forwarded to Java).  This satisfies the requirement to keep the
fetch step as a thin, separable pre-filter.

Credential safety: password / ssh_key / auth_token are used only for the
single fetch call and are never written to session JSON, brain state, logs,
or git-tracked files.  Callers must not log these values.
"""

import requests

# Vendor -> SSH command to dump running config.
# Generic fallback is "show running-config" which works for Cisco-like CLI.
VENDOR_COMMANDS = {
    "cisco": "show running-config",
    "juniper": "show configuration | display set",
    "generic": "show running-config",
}

# Default timeouts in seconds
SSH_TIMEOUT = 15
HTTP_TIMEOUT = 15


def get_vendor_command(vendor: str) -> str:
    """
    Return the vendor-appropriate config-dump command.
    Falls back to generic "show running-config" for unknown / auto.
    """
    if not vendor or vendor.strip().lower() == "auto":
        return VENDOR_COMMANDS["generic"]
    key = vendor.strip().lower()
    return VENDOR_COMMANDS.get(key, VENDOR_COMMANDS["generic"])


def fetch_via_ssh(host: str, username: str, password: str = None,
                  ssh_key: str = None, vendor: str = "auto",
                  port: int = 22, timeout: int = SSH_TIMEOUT,
                  vendor_command: str = None) -> str:
    """
    Open an SSH connection to host and run the vendor-appropriate
    config-dump command.  Returns the full command output as plain text.

    Either password or ssh_key (private key string or path) must be
    supplied alongside username.

    Raises exceptions on connection/auth/command failure — caller maps to
    HTTP 502 / 500.

    No credential is logged; only host / vendor / error class is safe to log.
    """
    try:
        import paramiko
    except ImportError as e:
        raise RuntimeError(f"paramiko not installed, SSH fetch unavailable: {e}")

    if not host or not host.strip():
        raise ValueError("SSH target host is required")
    if not username or not username.strip():
        raise ValueError("SSH username is required")
    # Require at least one auth method
    if (not password or not password.strip()) and (not ssh_key or not ssh_key.strip()):
        raise ValueError("SSH requires password or ssh_key")

    command = vendor_command.strip() if vendor_command and vendor_command.strip() else get_vendor_command(vendor)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    pkey = None
    key_file = None
    # ssh_key may be a file path or a PEM string; detect PEM header
    if ssh_key and ssh_key.strip():
        ks = ssh_key.strip()
        if "PRIVATE KEY" in ks:
            # PEM string — write to temp file for paramiko
            import tempfile
            import os
            # Use RSAKey / Ed25519 etc auto-detect via paramiko key parsing
            # Paramiko can load from string via StringIO, but pkey types vary.
            # Try each key type.
            from io import StringIO
            key_obj = None
            for key_cls in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]:
                try:
                    key_obj = key_cls.from_private_key(StringIO(ks), password=password if password else None)
                    break
                except Exception:
                    continue
            if key_obj is None:
                # Fallback: try as file path if it looks like a path
                if len(ks) < 512 and "\n" not in ks:
                    key_file = ks
                else:
                    raise ValueError("Unable to parse SSH private key (unsupported format)")
            else:
                pkey = key_obj
        else:
            # Treat as path
            if len(ks) < 512 and "/" in ks or ks.startswith("~") or ks.endswith(".pem") or ks.endswith(".key"):
                key_file = ks
            else:
                # Ambiguous — try as PEM once more with StringIO
                from io import StringIO
                key_obj = None
                for key_cls in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]:
                    try:
                        key_obj = key_cls.from_private_key(StringIO(ks))
                        break
                    except Exception:
                        continue
                if key_obj is not None:
                    pkey = key_obj
                else:
                    raise ValueError("ssh_key must be a PEM string or key file path")

    connect_kwargs = {
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
        connect_kwargs["pkey"] = pkey
    elif key_file is not None:
        connect_kwargs["key_filename"] = key_file
    elif password and password.strip():
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        # Paramiko exec_command timeout is per-channel; also wait for completion
        exit_code = stdout.channel.recv_exit_status()
        raw = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if exit_code != 0 and not raw.strip():
            raise RuntimeError(f"SSH command failed (exit {exit_code}): {err[:500]}")
        # Some devices include pagination prompts; raw is returned as-is
        return raw
    finally:
        try:
            client.close()
        except Exception:
            pass


def fetch_via_url(url: str, auth_token: str = None,
                  auth_header: str = None, timeout: int = HTTP_TIMEOUT) -> str:
    """
    Perform HTTP GET to url and capture response body as config text.
    Optional auth: if auth_token is supplied, it is sent as
    `auth_header` (default "Authorization") with Bearer prefix unless the
    token already looks like a full header value (contains space).
    Assumes plain-text / JSON / XML config content.
    """
    if not url or not url.strip():
        raise ValueError("URL target is required")
    u = url.strip()
    if not (u.lower().startswith("http://") or u.lower().startswith("https://")):
        raise ValueError("URL must start with http:// or https://")

    headers = {}
    if auth_token and auth_token.strip():
        hdr_name = auth_header.strip() if auth_header and auth_header.strip() else "Authorization"
        token = auth_token.strip()
        # If token already contains "Bearer " or similar, use as-is; else prefix Bearer
        if " " not in token and hdr_name.lower() == "authorization":
            headers[hdr_name] = f"Bearer {token}"
        else:
            headers[hdr_name] = token

    # No credential in logs; only URL host is safe (but token never logged)
    resp = requests.get(u, headers=headers, timeout=timeout)
    # Accept any 2xx; raise for error status
    resp.raise_for_status()
    # Prefer text; if binary, decode with replace
    # requests .text uses charset detection; fallback to content decode
    if resp.text is not None:
        # If response is JSON, return raw text (ingestion pipeline handles it as raw config)
        return resp.text
    return resp.content.decode("utf-8", errors="replace")


def fetch_config(source_type: str, target: str, vendor: str = "auto",
                 username: str = None, password: str = None,
                 ssh_key: str = None, auth_token: str = None,
                 auth_header: str = None, port: int = 22,
                 vendor_command: str = None, timeout: int = None) -> str:
    """
    Dispatch to SSH or HTTP fetch based on source_type ("ip" or "url").
    Returns raw config text string.

    This is the sole public entry for the bridge endpoint; it isolates
    retrieval from ingestion.  No parsing occurs here.
    """
    if not source_type or source_type.strip().lower() not in ("ip", "url"):
        raise ValueError("source_type must be 'ip' or 'url'")
    st = source_type.strip().lower()
    if not target or not target.strip():
        raise ValueError("target is required")

    if st == "ip":
        # Treat target as hostname/IP
        t = timeout if timeout else SSH_TIMEOUT
        return fetch_via_ssh(
            host=target,
            username=username,
            password=password,
            ssh_key=ssh_key,
            vendor=vendor,
            port=port,
            timeout=t,
            vendor_command=vendor_command,
        )
    else:
        t = timeout if timeout else HTTP_TIMEOUT
        return fetch_via_url(
            url=target,
            auth_token=auth_token,
            auth_header=auth_header,
            timeout=t,
        )
