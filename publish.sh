echo "Make sure to bump the version in PKG-INFO first"

rm ./dist/*

python setup.py sdist bdist_wheel 

twine upload dist/*
