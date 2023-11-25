# pwdtools

## Description
`pwdtools` is a set of tools for managing password security. It includes a library (`pwdlib`) and a main script (`pwdtools.py`). It's quite basic currently but I'm working on expanding it!

## Installation
To install `pwdtools`, you need to have `pip3` installed on your system. Then, you can use the provided Makefile:

```bash
make install
```

This will install the necessary Python dependencies, copy the `pwdtools.py` script and `pwdlib` directory to your local bin directory (`/usr/local/bin` by default), and set the necessary permissions.

## Uninstallation
To uninstall `pwdtools`, you can use the provided Makefile:

```
make uninstall
```

This will remove the `pwdtools.py` script and `pwdlib` directory from your local bin directory.

## Usage
After installation, you can run `pwdtools` from any location in your terminal:

```
pwdtools --check <your_password>
pwdtools --generate
pwdtools --hash <string>
pwdtools --busthash <hash>
...
```

Run `pwdtools --help` for more information

## Contributing
Contributions are welcome, but keep in mind this is just a small project so just shoot me a message first. Please fork the project and create a pull request with your changes.

## License
This project is licensed under the terms of the MIT license.
