UID := $(shell id -u)

venv:
	python3 -m venv venv
	./venv/bin/pip install -U pip wheel
	./venv/bin/pip install -r requirements.txt

clean:
	rm -ef venv

web: venv
	CONFIG=./config.yml ./venv/bin/uvicorn main:app --reload

update:
	curl --silent -o debian_cve.json https://security-tracker.debian.org/tracker/data/json

image:
	docker build \
		-t trivy-my-debian \
		--build-arg UID=$(UID) \
		.
