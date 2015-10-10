build:
	python setup.py build

install:
	python setup.py install

clean:
	rm -rf build dist bitjws.egg-info tests/__pycache__ bitjws/__pycache__
	rm -rf tests/*.pyc bitjws/*.pyc *.egg
