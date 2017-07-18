try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='certsrv',
    description='A Python client for the Microsoft AD Certificate Services web page',
    author='Magnus Watn',
    license='MIT',
    url='https://github.com/magnuswatn/certsrv',
    keywords='ad adcs certsrv pki certificate',
    version='1.5.1',
    py_modules=['certsrv'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Systems Administration',
        ],
)
