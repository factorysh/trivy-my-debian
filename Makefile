venv:
	python3 -m venv venv
	./venv/bin/pip install -U pip wheel
	./venv/bin/pip install -r requirements.txt

clean:
	rm -ef venv

web:
	uvicorn main:app --reload
