import json
import os
from typing import Literal, Optional, get_args

import click

import crunch_certificate.certificate as certificate
import crunch_certificate.constants as constants
import crunch_certificate.pem as pem
import crunch_certificate.sign as sign
from crunch_certificate.__version__ import __version__

ENVIRONMENT_PRODUCTION = "production"
ENVIRONMENT_STAGING = "staging"
ENVIRONMENT_DEVELOPMENT = "development"

ENVIRONMENT_ALIASES = {
    "prod": ENVIRONMENT_PRODUCTION,
    "test": ENVIRONMENT_STAGING,
    "dev": ENVIRONMENT_DEVELOPMENT,
    "local": ENVIRONMENT_DEVELOPMENT,
}

ENVIRONMENTS = {
    ENVIRONMENT_PRODUCTION: (constants.CRUNCH_API_BASE_URL_PRODUCTION, constants.CPI_API_BASE_URL_PRODUCTION),
    ENVIRONMENT_STAGING: (constants.CRUNCH_API_BASE_URL_STAGING, constants.CPI_API_BASE_URL_STAGING),
    ENVIRONMENT_DEVELOPMENT: (constants.CRUNCH_API_BASE_URL_DEVELOPMENT, constants.CPI_API_BASE_URL_DEVELOPMENT),
}


the_crunch_api_base_url: str = None  # type: ignore
the_cpi_api_base_url: str = None  # type: ignore


@click.group()
@click.option("--crunch-api-base-url", envvar=constants.CRUNCH_API_BASE_URL_ENV_VAR, default=constants.CRUNCH_API_BASE_URL_PRODUCTION, help="Set the API base url.")
@click.option("--cpi-api-base-url", envvar=constants.CPI_API_BASE_URL_ENV_VAR, default=constants.CPI_API_BASE_URL_PRODUCTION, help="Set the Web base url.")
@click.option("--environment", "--env", "environment_name", envvar=constants.ENVIRONMENT_ENV_VAR, help="Connect to another environment.")
@click.version_option(__version__, package_name="__version__.__title__")
def cli(
    crunch_api_base_url: str,
    cpi_api_base_url: str,
    environment_name: str,
):
    global the_crunch_api_base_url, the_cpi_api_base_url
    the_crunch_api_base_url = crunch_api_base_url
    the_cpi_api_base_url = cpi_api_base_url

    environment_name = ENVIRONMENT_ALIASES.get(environment_name) or environment_name
    if environment_name in ENVIRONMENTS:
        print(f"environment: forcing {environment_name} urls, ignoring ${constants.CRUNCH_API_BASE_URL_ENV_VAR} and ${constants.CPI_API_BASE_URL_ENV_VAR}")

        the_crunch_api_base_url, the_cpi_api_base_url = ENVIRONMENTS[environment_name]
    elif environment_name:
        print(f"environment: unknown environment `{environment_name}`, ignoring it")


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
@click.option("--ca-key-path", type=click.Path(dir_okay=False, readable=True, exists=True), required=False)
@click.option("--ca-cert-path", type=click.Path(dir_okay=False, readable=True, exists=True), required=False)
@click.option("--common-name", type=str, required=True, prompt=True)
@click.option("--san-dns", type=str, required=False)
@click.option("--target", type=click.Choice(get_args(TargetProfileString)), required=False)
@click.option("--key-path", type=click.Path(dir_okay=False, writable=True), default="tls.key", prompt=True)
@click.option("--cert-path", type=click.Path(dir_okay=False, writable=True), default="tls.crt", prompt=True)
@click.option("--overwrite", is_flag=True)
def tls_generate(
    ca_key_path: Optional[str],
    ca_cert_path: Optional[str],
    common_name: str,
    san_dns: Optional[str],
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

    if bool(ca_key_path) ^ bool(ca_cert_path):
        click.echo(f"{cert_path}: both `--ca-key-path ca.key` and `--ca-cert-path ca.crt` must be used at the time", err=True)
        raise click.Abort()

    if ca_key_path and ca_cert_path:
        with open(ca_key_path) as fd:
            ca_key = pem.loads_private_key(fd.read())
        click.echo(f"ca: {ca_key_path}: loaded key")

        with open(ca_cert_path) as fd:
            ca_cert = pem.loads_certificate(fd.read())
        click.echo(f"ca: {ca_cert_path}: loaded certificate")

        certificate_issuer = certificate.LocalTlsCertificateIssuer(
            ca_key=ca_key,
            ca_cert=ca_cert,
        )
    else:
        certificate_issuer = certificate.RemoteTlsCertificateIssuer(
            api_base_url=the_crunch_api_base_url,
        )

    if target == "coordinator":
        is_client = True
        is_server = False
    elif target == "cruncher":
        is_client = False
        is_server = True
    else:
        is_client = True
        is_server = True

    (
        tls_key,
        tls_cert,
    ) = certificate.generate_tls(
        certificate_issuer=certificate_issuer,
        common_name=common_name,
        san_dns=san_dns,
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
@click.option("--hot-key", type=str, required=False)
@click.option("--model-id", type=str, required=False)
@click.option("--tls-cert-path", type=click.Path(dir_okay=False, readable=True, exists=True), default="tls.crt")
@click.option("--wallet-path", type=click.Path(dir_okay=False, readable=True, exists=True), required=False)
@click.option("--output", "output_file_path", type=click.Path(dir_okay=False, writable=True), required=False)
def sign_command(
    tls_cert_path: str,
    hot_key: Optional[str],
    model_id: str,
    wallet_path: Optional[str],
    output_file_path: Optional[str],
):
    with open(tls_cert_path) as fd:
        tls_cert = pem.loads_certificate(fd.read())
    click.echo(f"tls: {tls_cert_path}: loaded certificate")

    if hot_key is not None:
        hot_key_provider = sign.StaticHotKeyProvider(
            value=hot_key,
        )
    else:
        hot_key_provider = sign.CpiHotKeyProvider(
            api_base_url=the_cpi_api_base_url,
        )

    if wallet_path is not None:
        signer = sign.KeypairSigner.load(
            wallet_path=wallet_path,
        )
    else:
        signer = sign.BrowserExtensionSigner()

    signed_message = signer.sign(
        cert_pub=certificate.get_public_key_as_string(tls_cert),
        hot_key_provider=hot_key_provider,
        model_id=model_id,
    )

    if output_file_path:
        with open(output_file_path, "w") as fd:
            json.dump(signed_message.to_dict(), fd, indent=2)
        click.echo(f"signed message: saved to {output_file_path}")
