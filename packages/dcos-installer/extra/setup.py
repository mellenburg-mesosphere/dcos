from setuptools import setup


setup(
    name='dcos_image',
    version='0.1',
    description='Server and CLI for deploying DC/OS on premise',
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
    packages=['dcos_installer'],
    install_requires=[
        'aiohttp==0.22.5',
        'analytics-python',
        'coloredlogs',
        'passlib',
        'py',
        'pyyaml',
        'requests==2.10.0',
        'keyring==9.1',  # FIXME: pin keyring to prevent dbus dep
    ],
    entry_points={
        'console_scripts': [
            'dcos_installer=dcos_installer.cli:main',
            'dcos-exhibitor-migrate-status=dcos_installer.exhibitor_migrate:status',
            'dcos-exhibitor-migrate-perform=dcos_installer.exhibitor_migrate:perform',
        ],
    },
    zip_safe=False
)
