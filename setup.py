from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="aim-environments",
    version="0.0.1",
    author="Mikhail Zolotukhin",
    author_email="mizolotu@jyu.fi",
    description="Docker-based network environments for intelligent cyber-security agent training",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mizolotu/Defender",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5',
)