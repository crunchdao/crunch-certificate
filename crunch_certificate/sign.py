import importlib.resources
import json
import socketserver
import webbrowser
from abc import ABC, abstractmethod
from base64 import b64encode
from collections import OrderedDict
from dataclasses import dataclass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from typing import Any, Dict, List, Optional
from typing import OrderedDict as OrderedDictType
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from solders.keypair import Keypair

__all__ = [
    "SignedMessage",
    "HotKeyProvider",
    "StaticHotKeyProvider",
    "CpiHotKeyProvider",
    "Signer",
    "BrowserExtensionSigner",
    "KeypairSigner",
    "create_message_as_bytes",
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


class HotKeyProvider(ABC):

    @abstractmethod
    def get(
        self,
        wallet_public_key: str,
    ) -> str:
        ...


class StaticHotKeyProvider(HotKeyProvider):

    def __init__(
        self,
        value: str,
    ):
        self.value = value

    def get(
        self,
        wallet_public_key: str,
    ) -> str:
        return self.value


class CpiHotKeyProvider(HotKeyProvider):

    def __init__(
        self,
        api_base_url: str,
    ):
        self.api_base_url = api_base_url

    def get(
        self,
        wallet_public_key: str,
    ) -> str:
        response = requests.get(
            url=urljoin(self.api_base_url, "/hotkeys"),
            params={
                "wallet": wallet_public_key,
            }
        )

        if not response.ok:
            raise ValueError(f"could not find hot_key: {response.status_code}: {response.text}")

        body = response.json()
        return body["hotkey"]


class Signer(ABC):

    @abstractmethod
    def sign(
        self,
        cert_pub: str,
        hot_key_provider: HotKeyProvider,
        model_id: str | None = None,
    ) -> SignedMessage:
        ...


class BrowserExtensionSigner(Signer):

    def sign(
        self,
        cert_pub: str,
        hot_key_provider: HotKeyProvider,
        model_id: str | None = None,
    ) -> SignedMessage:
        running = True

        got_message: Optional[bytes] = None
        got_public_key: Optional[str] = None
        got_signature: Optional[str] = None

        class Handler(SimpleHTTPRequestHandler):
            def _get_first(self, params: Dict[str, List[str]], name: str) -> Optional[str]:
                values = params.get(name)
                if values is not None:
                    return values[0]

            def do_GET(self):
                try:
                    parsed_path = urlparse(self.path)
                    params = parse_qs(parsed_path.query)

                    if parsed_path.path == "/message":
                        self.do_GET_message(
                            wallet_public_key=self._get_first(params, "publicKey")
                        )
                    elif parsed_path.path == "/result":
                        self.do_GET_result(
                            signature=self._get_first(params, "signature"),
                        )
                    else:
                        html = importlib.resources.read_text(__package__, "web_sign.html")  # type: ignore
                        self.send_html(html)
                except Exception as exception:
                    return self.send_json(
                        {
                            "message": f"Internal error: {exception}"
                        },
                        status=HTTPStatus.INTERNAL_SERVER_ERROR,
                    )

            def do_GET_message(
                self,
                wallet_public_key: Optional[str],
            ):
                if wallet_public_key is None:
                    return self.send_json(
                        {
                            "message": "Missing ?walletPublicKey query parameter"
                        },
                        status=HTTPStatus.BAD_REQUEST,
                    )

                hot_key = hot_key_provider.get(
                    wallet_public_key=wallet_public_key,
                )

                message_bytes = create_message_as_bytes(
                    cert_pub=cert_pub,
                    hot_key=hot_key,
                    model_id=model_id,
                )

                nonlocal got_message, got_public_key
                got_message = message_bytes
                got_public_key = wallet_public_key

                return self.send_json({
                    "message": list(message_bytes),
                    "hotKey": hot_key,
                })

            def do_GET_result(
                self,
                signature: Optional[str],
            ):
                if signature is None:
                    return self.send_json(
                        {
                            "message": "Missing ?signature query parameter"
                        },
                        status=HTTPStatus.BAD_REQUEST,
                    )

                nonlocal running, got_signature
                running = False
                got_signature = signature

                return self.send_json("OK")

            def send_html(self, content: str):
                encoded = content.encode()

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Content-Type", "text/html")
                self.end_headers()

                self.wfile.write(encoded)

            def send_json(self, object: Any, status: HTTPStatus = HTTPStatus.OK):
                encoded = json.dumps(object).encode()

                self.send_response(status)
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()

                self.wfile.write(encoded)

        port = self._find_open_port()

        with socketserver.TCPServer(("", port), Handler) as httpd:
            url = f"http://localhost:{port}"
            print(f"sign: open {url} in your browser")
            webbrowser.open_new_tab(url)

            while running:
                httpd.handle_request()

        assert got_public_key
        assert got_message
        assert got_signature

        return SignedMessage(
            message_b64=_base64_encode(got_message),
            wallet_pubkey_b58=got_public_key,
            signature_b64=got_signature,
        )

    def _find_open_port(self):
        import socket

        with socket.socket() as socket:
            socket.bind(("", 0))
            return socket.getsockname()[1]


class KeypairSigner(Signer):

    def __init__(self, wallet: Keypair):
        self._wallet = wallet

    def sign(
        self,
        cert_pub: str,
        hot_key_provider: HotKeyProvider,
        model_id: str | None = None,
    ) -> SignedMessage:
        public_key = str(self._wallet.pubkey())
        hot_key = hot_key_provider.get(public_key)

        message = create_message_as_bytes(
            cert_pub=cert_pub,
            hot_key=hot_key,
            model_id=model_id,
        )

        signature = self._wallet.sign_message(message)

        return SignedMessage(
            message_b64=_base64_encode(message),
            wallet_pubkey_b58=public_key,
            signature_b64=_base64_encode(bytes(signature)),
        )

    @staticmethod
    def load(wallet_path: str):
        with open(wallet_path) as file:
            wallet_data = file.read()

        wallet = Keypair.from_json(wallet_data)

        return KeypairSigner(wallet)


def create_message_as_bytes(
    *,
    cert_pub: str,
    hot_key: str,
    model_id: Optional[str] = None,
) -> bytes:
    message: OrderedDictType[str, str] = OrderedDict()

    message["cert_pub"] = cert_pub
    message["hot_key"] = hot_key

    if model_id is not None:
        message["model_id"] = model_id

    return json.dumps(message).encode("utf-8")
