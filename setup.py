import setuptools
from distutils.core import setup

pkgs = {
    "required": [
        "numpy",
        "scipy",
        "pandapower",
        "matplotlib",
        "seaborn",
        "colorsys",
        "networkx",
    ], 
}

setup(
    description='Threats2Power provides a high-level, abstract, representation of the communication network for power systems.',
    author='Xavier Weiss',
    author_email='xavierw@kth.se',
    python_requires='>=3.10',
    url="https://github.com/DEUCE1957/Threats2Power",
    packages=setuptools.find_packages(),
    install_requires=pkgs["required"],
)