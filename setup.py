from setuptools import setup, find_packages

setup(
    name="digital-forensics-file-analyzer",
    version="1.0.0",
    author="Sahil Maurya",
    author_email="sahilmaurya2575@gmail.com",
    description="A digital forensics tool that extracts file metadata, hashes, and EXIF data, with duplicate detection and report generation.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/sahilmaurya2006/digital-forensics-file-analyzer",
    packages=find_packages(),  # automatically finds 'src' package
    install_requires=[
        "tqdm",
        "colorama",
        "exifread",
        "pandas",
        "reportlab",
        "pillow"
    ],
    entry_points={
        "console_scripts": [
            "meta-analyze=src.analyzer:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security :: Forensics",
    ],
    python_requires=">=3.8",
)
 