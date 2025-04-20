pip install build
pip uninstall pylibjodi
rm -rf dist pylibjodi.egg-info
python -m build
pip install dist/*.whl