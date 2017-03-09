from setuptools import setup

setup(
    name='python-ssh',
    version='0.1',
    description='Helpers for stable single- and multi-tunnel SSH sessions',
    url='https://dcos.io',
    author='Mesosphere, Inc.',
    author_email='help@dcos.io',
    license='apache2',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    packages=['ssh'],
    zip_safe=False
)
