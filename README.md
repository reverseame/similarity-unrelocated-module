# Similarity Unrelocated Module - SUM

This is the adaptation of SUM to both Python 3 and Windows.

## Installation

To download the *windowsVersion* branch of this repository, execute the following command (the folder
*similarity-unrelocated-module* will be created):

```bash
git clone --single-branch --branch windowsVersion https://github.com/reverseame/similarity-unrelocated-module.git
```

Python 3 has to be installed on the Windows machine and the following Python packages have to be installed:
*capstone*, *pefile*, *distorm3*, and *py-tlsh*.

Additionally, a folder named *marked_pefile* has to be inside the *similarity-unrelocated-module* folder. To create that
folder, go to the directory where SUM has been downloaded and execute the following command:

```bash
git clone --single-branch --branch python3Version --depth 1 --recurse-submodules --shallow-submodules https://github.com/miguelmartinperez/markedPefile.git marked_pefile
```

Finally, SUM depends on two command line tools, which have to be manually downloaded and placed in the correct locations
for SUM to find them. These tools are listed below, as well as where to place them:

- [**sdhash**](https://github.com/sdhash/sdhash): In the *Releases* section, download the x64 ZIP file corresponding to
  version 4.0. After that, extract its contents and copy them to the
  *similarity-unrelocated-module/windows_dependencies/SDAs/sdhash* directory (after creating it).
- [**ssdeep**](https://ssdeep-project.github.io/ssdeep/index.html): Download the file named
  *ssdeep-2.14.1-win32-binary.zip* from [here](https://github.com/ssdeep-project/ssdeep/releases). Similarly to
  *sdhash*, extract the contents of the ZIP file and copy them to the
  *similarity-unrelocated-module/windows_dependencies/SDAs/ssdeep* directory (also after creating it).

## Usage

Details about how to use SUM and its functionality can be found in
the [master branch](https://github.com/reverseame/similarity-unrelocated-module).

## License

Licensed under the [GNU GPLv3](LICENSE) license.
