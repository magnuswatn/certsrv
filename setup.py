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
version = dict(re.findall(r"""__([a-z]+)__ = '([^']+)""", read_file(script_path)))['version']


setup(
    name='certsrv',
    description='A Python client for the Microsoft AD Certificate Services web page',
    author='Magnus Watn',
    license='MIT',
    url='https://github.com/magnuswatn/certsrv',
    keywords='ad adcs certsrv pki certificate',
    version=version,
    py_modules=['certsrv'],
    extras_require={
        'ntlm': ['python-ntlm']
        },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2 :: Only',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Systems Administration',
        ],
)
