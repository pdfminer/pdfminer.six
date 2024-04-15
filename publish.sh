echo "Make sure to make a tag before with git tag -a 1.0.0 -m \"Version 1.0.0\""
echo "Or better change the setup.py version"

rm ./dist/*

python setup.py build sdist bdist_wheel 

twine upload dist/*
