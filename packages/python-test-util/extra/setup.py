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
    install_requires=[
        'botocore',
        'boto3',
        'requests',
        'retrying',
        'msrest==0.4.0',
        'msrestazure==0.4.1',
        'azure-storage==0.32.0',
        'azure-mgmt-network==0.30.0rc4',
        'azure-mgmt-resource==0.30.0rc4',
        'passlib',
        'pyyaml',
        'gen',
        'pkgpanda',
        'ssh'],
    packages=['test_util'],
    zip_safe=False
)
