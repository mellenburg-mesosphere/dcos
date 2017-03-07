from setuptools import setup

setup(
    name='dcos-test-util',
    version='0.1',
    description='Helpers for Provisioning and Orchestrating DC/OS',
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
    packages=['test_util'],
    zip_safe=False
)
