from setuptools import setup

setup(
    name="ctfsolve",
    version="1.0",
    py_modules=["decoder"],
    entry_points={
        "console_scripts": [
            "ctfsolve=decoder:main",
        ],
    },
)


