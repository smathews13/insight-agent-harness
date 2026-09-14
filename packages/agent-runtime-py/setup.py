"""Compatibility shim for local builders that predate PEP 621 metadata."""

from pathlib import Path

from setuptools import find_packages, setup

setup(
    name="insight-agent-harness-runtime",
    version="0.1.0",
    description="Provider-neutral governed agent runtime interfaces and controls",
    long_description=Path(__file__).with_name("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    package_dir={"": "src"},
    packages=find_packages("src"),
    install_requires=[],
)
