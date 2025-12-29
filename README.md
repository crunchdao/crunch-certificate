# Crunch Certificate Tool

[![PyTest](https://github.com/crunchdao/crunch-certificate/actions/workflows/pytest.yml/badge.svg)](https://github.com/crunchdao/crunch-certificate/actions/workflows/pytest.yml)

This Python library is designed for the [CrunchDAO Platform](https://hub.crunchdao.com/), exposing the certificate tools in a very small CLI.

- [Crunch Certificate Tool](#crunch-certificate-tool)
- [Installation](#installation)
- [Usage](#usage)
  - [Generate a Key and a Certificate for the CA](#generate-a-key-and-a-certificate-for-the-ca)
  - [Generate a Key and a Certificate for the TLS Connection](#generate-a-key-and-a-certificate-for-the-tls-connection)
  - [Sign a Message](#sign-a-message)
- [Contributing](#contributing)
- [License](#license)

# Installation

Use [pip](https://pypi.org/project/crunch-certificate/) to install the `crunch-certificate` package.

```bash
pip install --upgrade crunch-certificate
```

# Usage

## Generate a Key and a Certificate for the CA

```bash
crunch-certificate ca generate
```

## Generate a Key and a Certificate for the TLS Connection

```bash
crunch-certificate tls generate
```

## Sign a Message

You will be prompted to sign the message using your browser extension. A web page with instructions will open.

```bash
crunch-certificate sign --hotkey my-hot-key --model-id 42
```

> [!TIP]
> You can also specify a wallet path using `--wallet-path <path-to-json-file>`.

# Contributing

Pull requests are always welcome! If you find any issues or have suggestions for improvements, please feel free to submit a pull request or open an issue in the GitHub repository.

# License

[MIT](https://choosealicense.com/licenses/mit/)
