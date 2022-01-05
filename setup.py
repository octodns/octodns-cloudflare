from setuptools import setup


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    with open('octodns_cloudflare/__init__.py') as fh:
        for line in fh:
            if line.startswith('__VERSION__'):
                return line.split("'")[1]


description, long_description = descriptions()

setup(
    author='Ross McFarland',
    author_email='rwmcfa1@gmail.com',
    description=description,
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-cloudflare',
    packages=('octodns_cloudflare',),
    python_requires='>=3.6',
    install_requires=('octodns>=0.9.14', 'requests>=2.27.0'),
    url='https://github.com/octodns/octodns-cloudflare',
    version=version(),
    tests_require=(
        'nose',
        'nose-no-network',
        'requests_mock',
    ),
)
