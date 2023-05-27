import os
import pkcs11
from pkcs11.util.x509 import decode_x509_public_key
import base64
import hashlib
from lxml import etree
from cryptography import x509
import argparse
import platform
from getpass import getpass

DEFAULT_LIB_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "libnstpkcs11.dylib")

def run(args):
    content_tree = etree.parse(args.input_file)
    can_content = etree.tostring(content_tree, method="c14n")
    can_content_sha512 = hashlib.sha512(can_content).digest()
    can_content_sha512_b64 = base64.b64encode(can_content_sha512)
    # We need to canonicalize the SignedInfo
    # https://www.di-mgt.com.au/xmldsig-c14n.html
    signed_info = b'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" /><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" /><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" /><DigestValue>' + can_content_sha512_b64 + b'</DigestValue></Reference></SignedInfo>'
    signed_info_can = etree.tostring(etree.fromstring(signed_info), method='c14n')

    lib_path = args.pkcs11_lib or DEFAULT_LIB_PATH
    # Load the PKCS11 library
    # https://python-pkcs11.readthedocs.io/en/latest/api.html#module-pkcs11.mechanisms
    lib = pkcs11.lib(lib_path)
    slots = lib.get_slots()
    for i, slot in enumerate(slots):
        print('Slot {0}:'.format(i))
        print('\n'.join(['    ' + slot_str_line for slot_str_line in str(slot).splitlines()]))
    
    if not slots:
        raise Exception('No slots found')
    elif len(slots) == 1:
        print('Using slot 0')
        slot_idx = 0
    else:
        slot_idx = int(input('Select slot number: '))
    
    token = slots[slot_idx].get_token()
    # Find key ID using unauthenticated session
    with token.open() as session:
        certs = session.get_objects({
          pkcs11.constants.Attribute.CLASS: pkcs11.constants.ObjectClass.CERTIFICATE,
        })
        certs_list = list(certs)
        for i, cert in enumerate(certs_list):
            cert_der = cert[pkcs11.constants.Attribute.VALUE]
            parsed_cert = x509.load_der_x509_certificate(cert_der)
            print('Cert {0}:'.format(i), parsed_cert.subject)
        if not certs_list:
            raise Exception('No certs found')
        elif len(certs_list) == 1:
            print('Using cert 0')
            cert_idx = 0
        else:
            cert_idx=int(input('Select cert number: '))

        selected_cert = certs_list[cert_idx]
        x509_b64 = base64.b64encode(selected_cert[pkcs11.constants.Attribute.VALUE])
        selected_modulus = decode_x509_public_key(selected_cert[pkcs11.constants.Attribute.VALUE])[pkcs11.constants.Attribute.MODULUS]

        selected_key_id = None
        for public_key in session.get_objects({
          pkcs11.constants.Attribute.CLASS: pkcs11.constants.ObjectClass.PUBLIC_KEY
        }):
            if public_key[pkcs11.constants.Attribute.MODULUS] == selected_modulus:
                selected_key_id = public_key.id
        if selected_key_id is None:
            raise Exception('No key corresponding to certificate found')
    
    # Sign using authenticated session
    pin = getpass('Enter PIN: ')
    with token.open(user_pin=pin) as session:
        private_key = session.get_key(
          object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY,
          id=selected_key_id
        )
        sign_result = private_key.sign(signed_info_can)
        signature_b64 = base64.b64encode(sign_result)

    signature_tree = etree.fromstring('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'
      + '<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />'
      + '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" />'
      + '<Reference URI="">'
      + '<Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /></Transforms>'
      + '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" /><DigestValue>' + can_content_sha512_b64.decode("utf-8") + '</DigestValue>'
      + '</Reference>'
      + '</SignedInfo>'
      + '<SignatureValue>' + signature_b64.decode("utf-8") + '</SignatureValue>'
      + '<KeyInfo><X509Data><X509Certificate>' + x509_b64.decode("utf-8") + '</X509Certificate></X509Data></KeyInfo>'
      + '</Signature>')
    content_tree.getroot().insert(1, signature_tree)
    signed_content = etree.tostring(content_tree, xml_declaration = True, encoding = "utf-8")
    open(args.output_file, 'wb').write(signed_content + b'\n')

def main():
    # Check processor type
    processor = platform.processor()
    if (processor != 'i386'):
        raise Exception('Unsupported processor type: ' + processor + '. This tool must be executed on i386 or under i386 emulation such as Rosetta')

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input-file', type=str, required=True, help='Path to the XML file to sign')
    parser.add_argument('-o', '--output-file', type=str, required=True, help='Path to the XML file to output')
    parser.add_argument('-l', '--pkcs11-lib', type=str, help='Path to PKCS11 library')
    args = parser.parse_args()

    run(args)


if __name__ == '__main__':
    main()
