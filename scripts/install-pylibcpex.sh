pip install build
pip uninstall pylibcpex
rm -rf dist pylibcpex.egg-info
python -m build
pip install dist/*.whl