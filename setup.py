from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ntfsforparser",
    version="1.0.0",
    author="Max Bendinelli",
    description="Framework Educativo Forense para particiones FAT, NTFS, Ext4 y contenedores E01",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/maxbendinelli/NTFSForParser",
    packages=find_packages(),
    py_modules=["main", "create_dummy_image", "create_e01_test"],
    install_requires=[
        "libewf-python"
    ],
    entry_points={
        "console_scripts": [
            "ntfsforparser=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
