#!/usr/bin/env python3
"""Create a new Codex-only Harness configuration without provider credentials."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--codex-executable", required=True, type=Path)
    parser.add_argument("--codex-home", required=True, type=Path)
    parser.add_argument("--codex-model", required=True)
    parser.add_argument("--codex-effort", choices=("minimal", "low", "medium", "high", "xhigh"), default="medium")
    parser.add_argument("--openssl", default="openssl", help="OpenSSL 3 executable")
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    if not args.directory.is_absolute():
        parser.error("directory must be absolute")
    def valid_runtime_path(path):
        return path.is_absolute() or (args.container and path.as_posix().startswith("/"))

    if not valid_runtime_path(args.codex_executable) or not valid_runtime_path(args.codex_home):
        parser.error("Codex executable and home must be absolute")
    if not args.owner_id or len(args.owner_id) > 128 or any(
        value not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@-" for value in args.owner_id
    ):
        parser.error("invalid owner ID")
    executable = shutil.which(args.openssl)
    if not executable:
        parser.error("OpenSSL 3 is required")

    os.umask(0o077)
    root = args.directory
    root.mkdir(mode=0o700)  # Never overwrite an existing node identity/state.

    def write(name, value):
        with (root / name).open("xb") as stream:
            stream.write(value.encode() if isinstance(value, str) else value)
            stream.flush()
            os.fsync(stream.fileno())

    def openssl(*values):
        result = subprocess.run([executable, *values], cwd=root, capture_output=True, timeout=15)
        if result.returncode:
            raise RuntimeError("OpenSSL operation failed; existing files were preserved")
        return result.stdout

    def certificate(name, *, client):
        openssl("req", "-new", "-newkey", "ed25519", "-noenc", "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + name)
        extended = "clientAuth" if client else "serverAuth"
        write(name + ".ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=" + extended + "\nsubjectAltName=DNS:localhost,DNS:codex,IP:127.0.0.1\n")
        openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", str(uuid.uuid4().int), "-days", "30", "-out", name + ".pem", "-extfile", name + ".ext")
        return hashlib.sha256(openssl("x509", "-in", name + ".pem", "-outform", "DER")).hexdigest()

    openssl("req", "-x509", "-newkey", "ed25519", "-noenc", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Harness Codex local CA", "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    certificate("node", client=False)
    gateway_pin = certificate("gateway", client=True)
    operator_pin = certificate("operator", client=True)
    node_id = str(uuid.uuid4())
    write("policy.txt", "Codex Harness deny-only smoke policy. No model turn may be started.\n")
    write("tools.json", "[]\n")
    for directory in ("node-data", "codex-state", "workspace"):
        (root / directory).mkdir(mode=0o700)
    (root / "codex-state" / "home").mkdir(mode=0o700)
    config = {
        "listen": "127.0.0.1:18443",
        "nodeId": node_id,
        "ownerId": args.owner_id,
        "dataDir": str(root / "node-data"),
        "registryVersion": 1,
        "certificateFile": str(root / "node.pem"),
        "keyFile": str(root / "node.key"),
        "clientCAFile": str(root / "ca.pem"),
        "gatewayCertificateSHA256": gateway_pin,
        "operatorCertificateSHA256": operator_pin,
        "policyFile": str(root / "policy.txt"),
        "toolManifestFile": str(root / "tools.json"),
        "policyRevision": "codex-deny-v1",
        "adapter": "codex",
        "codex": {
            "executable": str(args.codex_executable),
            "stateDir": str(root / "codex-state"),
            "workingDir": str(root / "workspace"),
            "codexHome": str(args.codex_home),
            "homeDir": str(root / "codex-state" / "home"),
            "model": args.codex_model,
            "effort": args.codex_effort,
        },
    }
    write("node.json", json.dumps(config, separators=(",", ":")) + "\n")
    if args.container:
        destination = root / "node-config"
        destination.mkdir(mode=0o700)
        for name in ("ca.pem", "node.pem", "node.key", "policy.txt", "tools.json"):
            shutil.copyfile(root / name, destination / name)
        container_config = dict(config)
        container_config.update(listen="0.0.0.0:18443", dataDir="/state/node")
        for field in ("certificateFile", "keyFile", "clientCAFile", "policyFile", "toolManifestFile"):
            container_config[field] = "/config/" + Path(container_config[field]).name
        container_config["codex"] = dict(config["codex"])
        container_config["codex"].update(
            executable="/opt/codex/node_modules/.bin/codex",
            stateDir="/state/codex",
            workingDir="/workspace",
            codexHome="/auth/codex",
            homeDir="/state/codex/home",
        )
        (destination / "node.json").write_text(json.dumps(container_config, separators=(",", ":")) + "\n")
    print(json.dumps({"directory": str(root), "nodeId": node_id, "ownerId": args.owner_id}))


if __name__ == "__main__":
    main()
