import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

version = {}
with open(r"acmetk/version.py") as fp:
    exec(fp.read(), version)

dependencies = [
    "acme==1.9.0",
    "acme-tiny==4.1.0",
    "aiohttp==3.7.4",
    "aiohttp_jinja2==1.4.2",
    "alembic==1.4.3",
    "asyncpg==0.21.0",
    "certbot==1.10.1",
    "click==7.1.2",
    "cryptography==3.3.2",
    "dnspython==2.0.0",
    "infoblox-client==0.5.0",
    "josepy~=1.7.0",
    "psycopg2==2.8.6",
    "PyYAML==5.4",
    "sqlalchemy==1.4.0b1",
    "trustme==0.6.0",
]

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
    install_requires=dependencies,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
