#!/usr/bin/env python3
"""Ephemeral HTTPS and SFTP servers for native curl-worker integration tests."""

from __future__ import annotations

import datetime
import io
import ipaddress
import json
import os
import signal
import socket
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import paramiko
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PAYLOAD = b"fmd-transfer-fixture\n"
USERNAME = "fixture"
PASSWORD = "fixture-password"
KEY_PASSPHRASE = "fixture-passphrase"
STOP = threading.Event()


def write_tls_material(root: Path) -> tuple[Path, Path]:
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FMD fixture CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = root / "fixture-ca.pem"
    cert_path = root / "fixture-server.pem"
    key_path = root / "fixture-server-key.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


class HttpsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/payload.txt":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.send_header("ETag", '"fixture-v1"')
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class SftpAuthServer(paramiko.ServerInterface):
    def __init__(self, client_key: paramiko.PKey) -> None:
        self.client_key = client_key

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey" if username == USERNAME else ""

    def check_auth_password(self, username: str, password: str) -> int:
        if username == USERNAME and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if username == USERNAME and key.asbytes() == self.client_key.asbytes():
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, _chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class FixtureSftp(paramiko.SFTPServerInterface):
    def stat(self, path: str) -> paramiko.SFTPAttributes | int:
        if path != "/payload.txt":
            return paramiko.SFTP_NO_SUCH_FILE
        attributes = paramiko.SFTPAttributes()
        attributes.st_mode = 0o100600
        attributes.st_size = len(PAYLOAD)
        return attributes

    lstat = stat

    def open(
        self, path: str, flags: int, _attr: paramiko.SFTPAttributes
    ) -> paramiko.SFTPHandle | int:
        if path != "/payload.txt" or flags & (os.O_WRONLY | os.O_RDWR):
            return paramiko.SFTP_PERMISSION_DENIED
        handle = paramiko.SFTPHandle(flags)
        handle.readfile = io.BytesIO(PAYLOAD)
        return handle


def serve_sftp_connection(
    connection: socket.socket,
    host_key: paramiko.PKey,
    client_key: paramiko.PKey,
) -> None:
    transport = paramiko.Transport(connection)
    transport.add_server_key(host_key)
    transport.set_subsystem_handler("sftp", paramiko.SFTPServer, FixtureSftp)
    try:
        transport.start_server(server=SftpAuthServer(client_key))
        while transport.is_active() and not STOP.wait(0.05):
            pass
    except (EOFError, OSError, paramiko.SSHException):
        pass
    finally:
        transport.close()
        connection.close()


def serve_sftp(listener: socket.socket, host_key: paramiko.PKey, client_key: paramiko.PKey) -> None:
    listener.settimeout(0.2)
    while not STOP.is_set():
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        threading.Thread(
            target=serve_sftp_connection,
            args=(connection, host_key, client_key),
            daemon=True,
        ).start()


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="fmd-transfer-fixture-"))
    ca_path, cert_path, tls_key_path = write_tls_material(root)

    https = ThreadingHTTPServer(("127.0.0.1", 0), HttpsHandler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(cert_path, tls_key_path)
    https.socket = tls.wrap_socket(https.socket, server_side=True)
    threading.Thread(target=https.serve_forever, daemon=True).start()

    host_key = paramiko.ECDSAKey.generate()
    client_key = paramiko.ECDSAKey.generate()
    client_key_path = root / "fixture-client-key.pem"
    client_key.write_private_key_file(str(client_key_path), password=KEY_PASSPHRASE)

    sftp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sftp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sftp.bind(("127.0.0.1", 0))
    sftp.listen(8)
    threading.Thread(target=serve_sftp, args=(sftp, host_key, client_key), daemon=True).start()

    def stop(_signum: int, _frame: object) -> None:
        STOP.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(
        json.dumps(
            {
                "https_url": f"https://127.0.0.1:{https.server_port}/payload.txt",
                "ca_path": str(ca_path),
                "sftp_url": f"sftp://127.0.0.1:{sftp.getsockname()[1]}/payload.txt",
                "client_key_path": str(client_key_path),
                "key_passphrase": KEY_PASSPHRASE,
                "username": USERNAME,
                "password": PASSWORD,
                "payload": PAYLOAD.decode("ascii"),
            }
        ),
        flush=True,
    )
    while not STOP.wait(0.2):
        time.sleep(0.01)
    https.shutdown()
    https.server_close()
    sftp.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
