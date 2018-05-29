init:
    python3 -m pip install -r requirements.txt

test:
    python3 -m unittest -v tests/packets.py

.PHONY: init test


