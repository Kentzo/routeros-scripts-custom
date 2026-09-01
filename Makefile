ROUTER  ?= gateway
SSH     ?= ssh
SCP     ?= scp -O
SCRIPTS ?=

NAMES := $(patsubst %.rsc,%,$(SCRIPTS))

RSC_READ   = :local varSource [/file/get \"$$f\" value-name=contents]
RSC_CLEAN  = /file/remove \"$$f\"
RSC_FIND   = :local varID [/system/script/find where name=\"$$s\"]
RSC_UPSERT = :if ([:len \$$varID] > 0) do={ /system/script/set \$$varID source=\$$varSource$$p } else={ /system/script/add name=\"$$s\" source=\$$varSource$$p }

.PHONY: help install
.DEFAULT_GOAL := help

help:
	@echo 'usage: make install SCRIPTS="<script>..." [ROUTER=<host>]'
	@echo
	@echo '  SCRIPTS  paths of scripts to install, .rsc suffix optional,'
	@echo '           e.g. mod/homenet-dns or setup-homenet-dns.rsc'
	@echo '  ROUTER   ssh destination (default: $(ROUTER))'

install: $(addsuffix .rsc,$(NAMES))
	@test -n '$(strip $(NAMES))' || { echo 'make: SCRIPTS is empty, e.g. make install SCRIPTS=mod/homenet-dns' >&2; exit 1; }
	@set -e; for s in $(NAMES); do \
	    f=$${s##*/}.rsc; \
	    case "$$s" in mod/*) p=" policy=read";; *) p="";; esac; \
	    echo "install $$s -> $(ROUTER)"; \
	    $(SCP) "$$s.rsc" $(ROUTER):/; \
	    $(SSH) $(ROUTER) "$(RSC_READ); $(RSC_CLEAN); $(RSC_FIND); $(RSC_UPSERT)"; \
	done
