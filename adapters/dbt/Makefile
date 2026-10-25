ROOT := $(abspath ../..)
BIN := $(ROOT)/.venv/bin
DBT_VENV := .dbt-venv
DBT := $(abspath $(DBT_VENV))/bin/dbt
JAFFLE := demo/jaffle_shop
ART := $(abspath demo/artifacts)

.PHONY: demo tamper verify clean check-db

# never let the demo fall back to the DATABASE_URL in .env (that's neon)
check-db:
ifndef DATABASE_URL
	$(error set DATABASE_URL to a scratch postgres, e.g. postgresql+asyncpg://attest@127.0.0.1:54329/attest_dbt)
endif

$(DBT):
	python3 -m venv $(DBT_VENV)
	$(DBT_VENV)/bin/pip install -q dbt-core==1.12.6 dbt-duckdb==1.11.0

$(JAFFLE):
	git clone -q --depth 1 https://github.com/dbt-labs/jaffle_shop_duckdb.git $(JAFFLE)
	cp $(JAFFLE)/seeds/raw_orders.csv $(JAFFLE)/raw_orders.full.csv

# build, snapshot the artifacts (docs generate overwrites run_results.json), ingest
define run
	cd $(JAFFLE) && $(DBT) build --profiles-dir . -q
	mkdir -p $(ART)/$(1)
	cp $(JAFFLE)/target/run_results.json $(JAFFLE)/target/manifest.json $(ART)/$(1)/
	cd $(JAFFLE) && $(DBT) docs generate --profiles-dir . -q
	cp $(JAFFLE)/target/catalog.json $(ART)/$(1)/
	cd $(ROOT) && $(BIN)/attest-dbt ingest $(ART)/$(1) || true
endef

demo: check-db $(DBT) $(JAFFLE)
	cd $(ROOT) && $(BIN)/alembic upgrade head
	cp $(JAFFLE)/raw_orders.full.csv $(JAFFLE)/seeds/raw_orders.csv
	$(call run,1)
	# second build loses half the orders so the row check has something to catch
	head -n 50 $(JAFFLE)/raw_orders.full.csv > $(JAFFLE)/seeds/raw_orders.csv
	$(call run,2)
	cp $(JAFFLE)/raw_orders.full.csv $(JAFFLE)/seeds/raw_orders.csv

tamper: check-db
	cd $(ROOT) && $(BIN)/python $(abspath demo/tamper.py)

verify: check-db
	cd $(ROOT) && $(BIN)/attest verify

clean:
	rm -rf demo/artifacts $(JAFFLE)
