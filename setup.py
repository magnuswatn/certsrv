try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'A Python client for the Microsoft AD Certificate Services web page',
    'author': 'Magnus Watn',
    'url': 'https://github.com/magnuswatn/certsrv',
    'download_url': 'https://github.com/magnuswatn/certsrv',
    'version': '0.9',
    'py_modules': ['certsrv'],
    'name': 'certsrv'
}

setup(**config)
