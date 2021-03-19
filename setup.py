import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

version = {}
with open(r"acmetk/version.py") as fp:
    exec(fp.read(), version)

setuptools.setup(
    name="acmetk",
    version=version["__version__"],
    author="Noah Wöhler",
    author_email="noah.woehler@gmail.com",
    description="An ACME Broker for Automated Certificate Acquisition in University Environments",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/noahkw/acmetk",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
