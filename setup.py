from setuptools import setup

readme = open('./README.md').read()

classifiers = [
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 3",
    "Topic :: Software Development :: Libraries",
    "Topic :: Security :: Cryptography"
]

setup(
    name="bitjws",
    version="0.4.2",
    description='JWS using Bitcoin message signing',
    long_description=readme,
    author='Guilherme Polo',
    author_email='gp@deginner.com',
    url='https://github.com/g-p-g/bitjws',
    license='MIT',
    classifiers=classifiers,
    include_package_data=True,
    packages=['bitjws'],
    setup_requires=['pytest-runner'],
    install_requires=['base58', 'secp256k1'],
    tests_require=['pytest', 'pytest-cov']
)
