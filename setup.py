from setuptools import setup

setup(
    name = 'vanilla',
    packages = ['vanilla'],
    include_package_data = True,
    install_requires = [
        'flask',
    ],
)