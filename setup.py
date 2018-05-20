# Copyright (c) 2018 Marco Giusti

from os.path import join as joinpath, dirname, abspath
from setuptools import setup


SETUPDIR = abspath(dirname(__file__))


def version():
    glb = {}
    with open(joinpath(SETUPDIR, 'src', 'pwsafe.py')) as fp:
        for line in fp:
            if '__version__' in line:
                exec(line, glb)
                return glb['__version__']
    raise RuntimeError('__version__ not found')


def long_description():
    with open(joinpath(SETUPDIR, 'README')) as fp:
        return fp.read()


setup(
    name='pwsafe.py',
    version=version(),
    description='Python3 library to manipulate PasswordSafe V3 files.',
    long_description=long_description(),
    author='Marco Giusti',
    author_email='marco.giusti@posteo.de',
    license='MIT',
    url='https://github.com/marcogiusti/pwsafe.py',
    py_modules=['pwsafe'],
    package_dir={'': 'src'},
    install_requires=['twofish'],
    extras_require={
        'dev': [
            'pycodestyle',
            'pyflakes',
            'tox'
        ]
    },
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    )
)
