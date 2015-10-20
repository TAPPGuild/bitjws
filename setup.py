from setuptools import setup

readme = open('./README.rst').read()

classifiers = [
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 3",
    "Topic :: Software Development :: Libraries",
    "Topic :: Security :: Cryptography"
]

url = 'https://github.com/g-p-g/bitjws'

# Cut the readme before the second section start.
top = readme.find('Usage\n-----')
bottom = readme.find('.. |Build Status|')
more = ("Visit {} to see the full README, the\n"
        "issue tracker, and others.\n\n\n")
readme = readme[:top] + more.format(url) + readme[bottom:]


setup(
    name="bitjws",
    version="0.6.2",
    description='JWS using Bitcoin message signing',
    long_description=readme,
    author='Guilherme Polo',
    author_email='gp@deginner.com',
    url=url,
    license='MIT',
    classifiers=classifiers,
    include_package_data=True,
    packages=['bitjws'],
    setup_requires=['pytest-runner'],
    install_requires=['base58', 'secp256k1'],
    tests_require=['pytest', 'pytest-cov']
)
