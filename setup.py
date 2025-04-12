from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="WinIDS",
    version="1.4",
    author="Nandhan K",
    author_email="developer.nandhank@gmail.com",
    description="Windows-based Intrusion Detection System using machine learning and reinforcement learning for adaptive security",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Nandhan-KA/WinIDS",
    packages=find_packages(),
    package_data={
        'WinIDS': ['data/*', 'models/*'],
        'WinIDS.netmon': ['geoip_db/*'],
    },
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
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
        "pydivert>=2.1.0",
        "psutil>=5.9.0",
        "dnspython>=2.2.0",
        "requests>=2.27.0",
        "geoip2>=4.6.0",
        "scapy>=2.5.0",
    ],
    extras_require={
        "maps": [
            "cartopy>=0.20.0",
            "matplotlib-basemap>=1.2.2",
        ],
    },
    entry_points={
        "console_scripts": [
            "WinIDS-dashboard=WinIDS.pro_dashboard:main",
            "WinIDS-bridge=WinIDS.bridge:main",
            "WinIDS-monitor=WinIDS.monitor:main",
            "WinIDS-attack-panel=WinIDS.attack_panel:main",
            "winids=WinIDS.__main__:main",
            "winids-netmon=WinIDS.netmon.__main__:main",
            "WinIDS-netmon=WinIDS.netmon.__main__:main",
        ],
    },
) 