#!/usr/bin/env python

from setuptools import find_packages, setup


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    with open('octodns_cloudflare/__init__.py') as fh:
        for line in fh:
            if line.startswith('__version__'):
                return line.split("'")[1]
    return 'unknown'


description, long_description = descriptions()

tests_require = ('pytest', 'pytest-cov', 'pytest-network', 'requests_mock')

setup(
    author='Ross McFarland',
    author_email='rwmcfa1@gmail.com',
    description=description,
    extras_require={
        'dev': tests_require
        + (
            # we need to manually/explicitely bump major versions as they're
            # likely to result in formatting changes that should happen in their
            # own PR. This will basically happen yearly
            # https://black.readthedocs.io/en/stable/the_black_code_style/index.html#stability-policy
            'black>=24.3.0,<25.0.0',
            'build>=0.7.0',
            'isort>=5.11.5',
            'pyflakes>=2.2.0',
            'readme_renderer[md]>=26.0',
            'twine>=3.4.2',
        ),
        'test': tests_require,
    },
    install_requires=('octodns>=1.5.0', 'requests>=2.27.0'),
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-cloudflare',
    packages=find_packages(),
    python_requires='>=3.9',
    tests_require=tests_require,
    url='https://github.com/octodns/octodns-cloudflare',
    version=version(),
)
