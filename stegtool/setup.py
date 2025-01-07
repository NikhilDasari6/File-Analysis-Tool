from setuptools import setup, find_packages

setup(
    name="stegtool",
    version="1.0.0",
    author="Nikhil Dasari",
    author_email="nikhil060606@gmail.com",
    description="A file analysis and steganography tool for Linux.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/stegtool",
    packages=find_packages(),
    install_requires=[
        "Pillow>=8.0.0",
        "numpy>=1.19.0",
    ],
    entry_points={
        "console_scripts": [
            "stegtool=stegtool.stegtool:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.6",
)

