from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="MacIDS",
    version="1.3",
    author="Nandhan K",
    author_email="developer.nandhank@gmail.com",
    description="macOS-based Intrusion Detection System using machine learning for adaptive network security",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Nandhan-KA/MacIDS",
    packages=find_packages(),
    package_data={
        'macids': ['data/*', 'models/*'],
        'macids.netmon': ['geoip_db/*'],
    },
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.7",
    install_requires=[
        "tensorflow>=2.0.0",
        "numpy>=1.18.0",
        "pandas>=1.0.0",
        "matplotlib>=3.1.0",
        "scikit-learn>=0.22.0",
        "pillow>=7.0.0",
        "scapy>=2.5.0",     # Using scapy instead of pydivert for packet capture
        "psutil>=5.9.0",
        "dnspython>=2.2.0",
        "requests>=2.27.0",
        "geoip2>=4.6.0",
    ],
    entry_points={
        "console_scripts": [
            "macids=macids.__main__:main",
            "macids-netmon=macids.netmon.__main__:main",
        ],
    },
) 