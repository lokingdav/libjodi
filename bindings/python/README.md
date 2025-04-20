# Python bindings
Python bindings for the libjodi library.

**Requirements**

Requires Python 3.8+

**Installing pylibjodi and Dependencies**

Installation instructions...

** Install System-wide dependencies**
Follow the <a href="../../README.md" target="_blank">instructions</a> in the main  file to install the system-wide dependencies.

If you're using conda, you can install the dependencies using the following command:
```bash
conda install -c conda-forge libsodium curl
```

```bash
cd /path/to/libjodi # navigate to the root of the libjodi repository
pip install build # if you don't have it installed
python -m build # if this fails try: python -m build --no-isolation
pip install dist/*.whl # install the generated wheel file
```

**Basic Usage**
```python

import pylibjodi
```
