PYTHON ?= python3

.PHONY: smoke dashboard healthcheck poll-inbox install-systemd

smoke:
	./scripts/smoke-test.sh

dashboard:
	$(PYTHON) ./defendos.py serve

healthcheck:
	$(PYTHON) ./defendos.py healthcheck

poll-inbox:
	$(PYTHON) ./defendos.py poll-inbox

install-systemd:
	./scripts/install-systemd.sh
