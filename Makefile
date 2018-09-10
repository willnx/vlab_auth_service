PACKAGE=vlab-auth-service
DANGLERS=`docker images -q --filter "dangling=true"`


clean:
	-rm -rf build
	-rm -rf dist
	-rm -rf *.egg-info
	-rm -f tests/.coverage
	-docker rm $(docker ps -a | awk '{print $1}')
	-docker rmi $(DANGLERS)

build: clean
	python setup.py bdist_wheel --universal

uninstall:
	-pip uninstall -y $(PACKAGE)

install: uninstall build
	pip install -U dist/*.whl

test: uninstall install
	cd tests && nosetests -v --with-coverage --cover-package=vlab_auth_service

images: build
	docker build -t willnx/vlab-auth-service .

up: clean
	docker-compose up --abort-on-container-exit
