build:
	python setup.py build

install:
	python setup.py install

clean:
	rm -rf build dist bitjws.egg-info tests/__pycache__ bitjws/__pycache__
	rm -rf tests/*.pyc bitjws/*.pyc *.egg

rst:
	pandoc --from=markdown --to=rst --output=README.rst README.md
