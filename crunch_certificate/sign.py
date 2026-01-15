import importlib.resources
import json
import socketserver
import traceback
import webbrowser
from abc import ABC, abstractmethod
from base64 import b64encode
from collections import OrderedDict
from dataclasses import dataclass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from typing import Any, Optional
from typing import OrderedDict as OrderedDictType
from urllib.parse import parse_qs, urlparse

from solders.keypair import Keypair

__all__ = [
    "SignedMessage",
    "Signer",
    "KeypairSigner",
    "create_message",
]


@dataclass(kw_only=True)
class SignedMessage:
    message_b64: str
    wallet_pubkey_b58: str
    signature_b64: str

    def to_dict(self):
        return dict(self.__dict__)


def _base64_encode(data: bytes):
    return b64encode(data).decode("ascii")


class Signer(ABC):

    def sign_json(
        self,
        message: Any,
    ):
        json_message = json.dumps(message).encode("utf-8")
        signed_message = self.sign_raw(json_message)

        return signed_message

    @abstractmethod
    def sign_raw(
        self,
        message: bytes,
    ) -> SignedMessage:
        ...


class BrowserExtensionSigner(Signer):

    def sign_raw(
        self,
        message: bytes,
    ) -> SignedMessage:
        running = True

        public_key: Optional[str] = None
        signature: Optional[str] = None

        html_template = importlib.resources.read_text(__package__, "web_sign.html")  # type: ignore

        class Handler(SimpleHTTPRequestHandler):
            def do_GET(self):
                try:
                    nonlocal running, public_key, signature

                    parsed_path = urlparse(self.path)

                    params = parse_qs(parsed_path.query)

                    signature_param = params.get("signature")
                    if signature_param is not None:
                        signature = signature_param[0]
                    else:
                        signature = None

                    public_key_param = params.get("publicKey")
                    if public_key_param is not None:
                        public_key = public_key_param[0]
                    else:
                        public_key = None

                    if parsed_path.path == "/result" and signature and public_key:
                        running = False
                        self.send_html("OK")
                    else:
                        content = html_template.replace('"%MESSAGE_FROM_PYTHON%"', str([int(x) for x in message]))
                        self.send_html(content)
                except:
                    traceback.print_exc()

            def send_html(self, content: str):
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Content-Type", "text/html")
                self.end_headers()

                self.wfile.write(content.encode())

        port = self._find_open_port()

        with socketserver.TCPServer(("", port), Handler) as httpd:
            url = f"http://localhost:{port}"
            print(f"sign: open {url} in your browser")
            webbrowser.open_new_tab(url)

            while running:
                httpd.handle_request()

        assert public_key
        assert signature

        return SignedMessage(
            message_b64=_base64_encode(message),
            wallet_pubkey_b58=public_key,
            signature_b64=signature,
        )

    def _find_open_port(self):
        import socket

        with socket.socket() as socket:
            socket.bind(("", 0))
            return socket.getsockname()[1]


class KeypairSigner(Signer):

    def __init__(self, wallet: Keypair):
        self._wallet = wallet

    def sign_raw(
        self,
        message: bytes,
    ) -> SignedMessage:
        signature = self._wallet.sign_message(message)

        return SignedMessage(
            message_b64=_base64_encode(message),
            wallet_pubkey_b58=str(self._wallet.pubkey()),
            signature_b64=_base64_encode(bytes(signature)),
        )

    @staticmethod
    def load(wallet_path: str):
        with open(wallet_path) as file:
            wallet_data = file.read()

        wallet = Keypair.from_json(wallet_data)

        return KeypairSigner(wallet)


def create_message(
    *,
    cert_pub: str,
    hotkey: str,
    model_id: str | None = None,
) -> OrderedDictType[str, str]:
    message: OrderedDictType[str, str] = OrderedDict()
    message["cert_pub"] = cert_pub
    message["hotkey"] = hotkey
    if model_id:
        message["model_id"] = model_id

    return message
