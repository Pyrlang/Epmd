from setuptools import setup, find_packages

setup(
    name="epmd",
    version="1.0.0",
    description="Erlang Port Manager Daemon in Python/Asyncio",
    author="Erlang Solutions Ltd and S2HC Sweden AB",
    author_email="dmytro.lytovchenko@gmail.com,pyrlang@s2hc.com,amitgaru2@gmail.com",
    url="http://pyrlang.readthedocs.io/",
    packages=find_packages(),
    # The library requires either asyncio or Gevent, you can relax this
    # dependency if Gevent is not desired
    install_requires=[],
)
