import os
import re
import codecs

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


def read_file(filename, encoding='utf8'):
    """Read unicode from given file."""
    with codecs.open(filename, encoding=encoding) as fd:
        return fd.read()

# read version number from the script
here = os.path.abspath(os.path.dirname(__file__))
script_path = os.path.join(here, 'certsrv.py')
version = dict(re.findall(r"""__([a-z]+)__ = "([^"]+)""", read_file(script_path)))['version']

readme = read_file(os.path.join(here, 'README.rst'))


setup(
    name='certsrv',
    description='A Python client for the Microsoft AD Certificate Services web page',
    long_description=readme,
    author='Magnus Watn',
    license='MIT',
    url='https://github.com/magnuswatn/certsrv',
    keywords='ad adcs certsrv pki certificate',
    version=version,
    py_modules=['certsrv'],
    install_requires=[
        'requests',
        ],
    extras_require={
        'ntlm': ['requests_ntlm'],
        'gssapi': ['requests-gssapi'],
        },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Systems Administration',
        ],
)
