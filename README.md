This tool allows you to sign XMLs on Mac using Serbian MUP-issued smart cards, e.g. HOV-DA2 reports
for NBS.

# Installation

This tool must be run with x86 Python in order to be compatible with x86 PKCS11 libraries.
- Find an Intel-only Python installer on https://www.python.org/downloads/
- Install it. Note the installation location such as `/Library/Frameworks/Python.framework/Versions/3.9`
- Use the newly installed pip instance to install mup-xml-sign: `/Library/Frameworks/Python.framework/Versions/3.9/bin/pip3 install mup-xml-sign`
- The `mup-xml-sign` tool is now installed at `/Library/Frameworks/Python.framework/Versions/3.9/bin/mup-xml-sign`
# Usage

- Locate the path of your unsigned XML file, such as `/path/to/unsigned.xml`
- Choose a path for your signed XML file, such as `/path/to/signed.xml`
- Insert MUP-issued smart card into card reader
- Run the tool:

```
/Library/Frameworks/Python.framework/Versions/3.9/bin/mup-xml-sign -i /path/to/unsigned.xml -o /path/to/signed.xml
```

- If you have multiple card readers, you will be prompted to choose one interactively
- If you have multiple certificates, you will be prompted to choose one interactively
- You will be prompted for your PIN interactively
- The signed XML will be written to `/path/to/signed.xml`

# Advanced Usage

- By default `mup-xml-sign` will use the macOS library for MUP-issued smart cards, known as
`libnstpkcs11.dylib`. You can try using other PKCS11 libraries by using the `-l` parameter. This
should allow a number of different configurations:
  - Using `mup-xml-sign` with non-MUP smart cards (e.g. Pošta-issued security devices)
  - Using `mup-xml-sign` with MUP-issued smart cards on Linux

However, these configurations have not been tested.

# Credits

`libnstpkcs11.dylib` was copied from this project: https://github.com/OpenSerbianEID/ePorezi/
