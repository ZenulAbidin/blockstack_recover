#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='blockstack_recover',
    version="1.1.0",
    url='https://github.com/ZenulAbidin/blockstack-recover',
    license='GPLv3',
    author='Ali Sherief',
    author_email='alihsherief@linuxmail.org',
    description='Wallet recovery tool for blockstack-client legacy wallets',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    #scripts=['bin/blockstack-recover'],
    entry_points='''
        [console_scripts]
        blockstack-recover=blockstack_recover.recover:main
    ''',
    download_url='https://github.com/ZenulAbidin/blockstack-recover/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'base58==2.1.0',
        'bitcoin==1.1.42',
        'blockstack-recover==1.0.0',
        'cachetools==4.2.1',
        'ecdsa==0.16.1',
        'pycrypto==2.6.1',
        'six==1.15.0',
        'utilitybelt==0.2.6',
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
