from setuptools import setup, find_packages


with open("README.md") as f:
    LONG_DESCRIPTION = f.read()


setup(
    name="imapbackup3",
    version="0.2",
    author="David M. Straub <straub@pm.me>",
    author_email="straub@pm.me",
    url="https://github.com/DavidMStraub/imapbackup3",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    license="MIT",
    packages=find_packages(),
    entry_points={"console_scripts": ["imapbackup3=imapbackup3.cli:main"]},
)
