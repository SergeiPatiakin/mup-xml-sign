from setuptools import setup

setup(name='mup-xml-sign',
    version='0.1.2',
    description='mup-xml-sign',
    url='http://github.com/SergeiPatiakin/mup-xml-sign',
    author='Sergei Patiakin',
    author_email='sergei.patiakin@gmail.com',
    license='Public Domain',
    packages=['mup_xml_sign'],
    scripts=['bin/mup-xml-sign'],
    python_requires='>=3.7',
    install_requires=[
        'cryptography~=40.0.2',
        'lxml~=4.9.2',
        'python-pkcs11~=0.7.0',
    ],
    include_package_data=True,
)
