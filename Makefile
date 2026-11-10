.PHONY: setup run test evaluate benchmark docker stop

setup:
	python3 -m pip install -r requirements.txt
run:
	python3 -m threatscope.app
test:
	python3 -m pytest -q
evaluate:
	python3 -m threatscope.evaluate
benchmark:
	python3 -m threatscope.benchmark
docker:
	docker compose up --build -d
stop:
	docker compose down
