import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aws-lambda-type-annotations",
    version="0.0.1",
    author="Trevor Leach",
    author_email="r33fshark-github@yahoo.com",
    description="AWS Lambda Type hints",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trevor-leach/aws-lambda-type-annotations",
    #packages=[''],
    package_dir={'': 'src'},
    classifiers=[
        'Programming Language :: Python :: 2.7',
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'Environment :: Console',
    ],
    install_requires=[
        'typing >= 3.7.4; python_version < "3.5"',
        'typing-extensions>=3.7.4 ; python_version<"3.8"'
    ]
)
