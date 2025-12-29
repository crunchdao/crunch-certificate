import os
from typing import Literal, Optional, get_args

import click

import crunch_certificate.certificate as certificate
import crunch_certificate.pem as pem
import crunch_certificate.sign as sign
from crunch_certificate.__version__ import __version__


@click.group()
@click.version_option(__version__, package_name="__version__.__title__")
def cli():
    pass  # pragma: no cover


@cli.group(name="ca")
def ca_group():
    pass  # pragma: no cover


@ca_group.command(name="generate")
@click.option("--common-name", type=str, required=True, prompt=True)
@click.option("--organization-name", type=str, required=True, prompt=True)
@click.option("--key-path", type=click.Path(dir_okay=False, writable=True), default="ca.key", prompt=True)
@click.option("--cert-path", type=click.Path(dir_okay=False, writable=True), default="ca.crt", prompt=True)
@click.option("--overwrite", is_flag=True)
def ca_generate(
    common_name: str,
    organization_name: str,
    key_path: str,
    cert_path: str,
    overwrite: int,
):
    if os.path.exists(key_path) and not overwrite:
        click.echo(f"{key_path}: file already exists (bypass using --overwrite)", err=True)
        raise click.Abort()

    if os.path.exists(cert_path) and not overwrite:
        click.echo(f"{cert_path}: file already exists (bypass using --overwrite)", err=True)
        raise click.Abort()

    (
        ca_key,
        ca_cert,
    ) = certificate.generate_ca(
        common_name=common_name,
        organization_name=organization_name,
    )

    ca_key_pem = pem.dumps(private_key=ca_key)
    ca_cert_pem = pem.dumps(certificate=ca_cert)

    with open(key_path, "w") as fd:
        fd.write(ca_key_pem)
    click.echo(f"ca: {key_path}: saved key")

    with open(cert_path, "w") as fd:
        fd.write(ca_cert_pem)
    click.echo(f"ca: {cert_path}: saved certificate")


@cli.group(name="tls")
def tls_group():
    pass  # pragma: no cover


TargetProfileString = Literal["coordinator", "cruncher"]


@tls_group.command(name="generate")
@click.option("--ca-key-path", type=click.Path(dir_okay=False, readable=True, exists=True), default="ca.key")
@click.option("--ca-cert-path", type=click.Path(dir_okay=False, readable=True, exists=True), default="ca.crt")
@click.option("--common-name", type=str, required=True, prompt=True)
@click.option("--target", type=click.Choice(get_args(TargetProfileString)), required=False)
@click.option("--key-path", type=click.Path(dir_okay=False, writable=True), default="tls.key", prompt=True)
@click.option("--cert-path", type=click.Path(dir_okay=False, writable=True), default="tls.crt", prompt=True)
@click.option("--overwrite", is_flag=True)
def tls_generate(
    ca_key_path: str,
    ca_cert_path: str,
    common_name: str,
    target: Optional[TargetProfileString],
    key_path: str,
    cert_path: str,
    overwrite: int,
):
    if os.path.exists(key_path) and not overwrite:
        click.echo(f"{key_path}: file already exists (bypass using --overwrite)", err=True)
        raise click.Abort()

    if os.path.exists(cert_path) and not overwrite:
        click.echo(f"{cert_path}: file already exists (bypass using --overwrite)", err=True)
        raise click.Abort()

    with open(ca_key_path) as fd:
        ca_key = pem.loads_private_key(fd.read())
    click.echo(f"ca: {ca_key_path}: loaded key")

    with open(ca_cert_path) as fd:
        ca_cert = pem.loads_certificate(fd.read())
    click.echo(f"ca: {ca_cert_path}: loaded certificate")

    if target == "coordinator":
        is_client = True
        is_server = False
    elif target == "cruncher":
        is_client = True
        is_server = False
    else:
        is_client = True
        is_server = True

    (
        tls_key,
        tls_cert,
    ) = certificate.generate_tls(
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name=common_name,
        is_client=is_client,
        is_server=is_server,
    )

    tls_key_pem = pem.dumps(private_key=tls_key)
    tls_cert_pem = pem.dumps(certificate=tls_cert)

    with open(key_path, "w") as fd:
        fd.write(tls_key_pem)
    click.echo(f"tls: {key_path}: saved key")

    with open(cert_path, "w") as fd:
        fd.write(tls_cert_pem)
    click.echo(f"tls: {cert_path}: saved certificate")


@cli.command(name="sign")
@click.option("--tls-cert-path", type=click.Path(dir_okay=False, readable=True, exists=True), default="tls.crt")
@click.option("--hotkey", type=str, required=True)
@click.option("--model-id", type=str, required=True)
@click.option("--tls-cert-path", type=click.Path(dir_okay=False, readable=True, exists=True), default="tls.crt")
@click.option("--wallet-path", type=click.Path(dir_okay=False, readable=True, exists=True), required=False)
def sign_command(
    tls_cert_path: str,
    hotkey: str,
    model_id: str,
    wallet_path: Optional[str],
):
    with open(tls_cert_path) as fd:
        tls_cert = pem.loads_certificate(fd.read())
    click.echo(f"tls: {tls_cert_path}: loaded certificate")

    # TODO Use real values
    message = sign.create_message(
        cert_pub=certificate.get_public_key_as_string(tls_cert),
        hotkey=hotkey,
        model_id=model_id,
    )

    if wallet_path is not None:
        signer = sign.KeypairSigner.load(wallet_path)
    else:
        signer = sign.BrowserExtensionSigner()
    
    signed_message = signer.sign_json(message)

    print(f"message_b64       : {signed_message.message_b64}")
    print(f"wallet_pubkey_b58 : {signed_message.wallet_pubkey_b58}")
    print(f"signature_b64     : {signed_message.signature_b64}")
