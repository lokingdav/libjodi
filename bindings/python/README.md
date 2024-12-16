# Python bindings
Python bindings for the libcpex library.

**Requirements**

Requires Python 3.8+

**Installing pylibcpex and Dependencies**

Installation instructions...

** Install System-wide dependencies**
Follow the <a href="../../README.md" target="_blank">instructions</a> in the main  file to install the system-wide dependencies.

If you're using conda, you can install the dependencies using the following command:
```bash
conda install -c conda-forge libsodium curl
```

```bash
cd /path/to/libcpex # navigate to the root of the libcpex repository
pip install build # if you don't have it installed
python -m build # if this fails try: python -m build --no-isolation
pip install dist/*.whl # install the generated wheel file
```

**Basic Usage**
```python

import pylibcpex
```
