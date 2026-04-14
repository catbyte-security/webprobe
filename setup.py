from setuptools import setup, find_packages

setup(
    name="webprobe",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.27",
        "beautifulsoup4>=4.12",
        "click>=8.1",
        "rich>=13.0",
        "lxml>=5.0",
    ],
    entry_points={
        "console_scripts": [
            "webprobe=webprobe.cli:cli",
        ],
    },
    python_requires=">=3.10",
)
