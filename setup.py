# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['pyafl_qemu_trace', 'pyafl_qemu_trace.binaries']

package_data = \
{'': ['*']}

setup_kwargs = {
    'name': 'pyafl-qemu-trace',
    'version': '0.1.0',
    'description': 'A pip-installable distribution of afl-qemu-trace.',
    'long_description': None,
    'author': 'novafacing',
    'author_email': 'rowanbhart@gmail.com',
    'maintainer': None,
    'maintainer_email': None,
    'url': None,
    'packages': packages,
    'package_data': package_data,
    'python_requires': '>=3.6,<4.0',
}
from build import *
build(setup_kwargs)

setup(**setup_kwargs)
