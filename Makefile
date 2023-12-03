# See LICENSE for licensing information.

VSN     = $(shell git describe --always --tags --abbrev=0 | sed 's/^v//')
PROJECT = $(notdir $(PWD))
TARBALL = $(PROJECT)-$(VSN)

DIALYZER = dialyzer
REBAR   := $(shell which rebar3 2>/dev/null)
REBAR   := $(if $(REBAR),$(REBAR),$(shell which rebar 2>/dev/null))

ifeq (,$(REBAR))
$(error rebar and rebar3 not found!)
endif

.PHONY : all clean test docs doc clean-docs dialyzer

all:
	@$(REBAR) compile

clean:
	@$(REBAR) $@
	@rm -rf ebin erl_crash.dump _build

path:
	@echo $(shell $(REBAR) $@)

doc:
	mkdir -p $@
	$(REBAR) ex_doc

test:
	@$(REBAR) eunit

info:
	@make -C c_src $@

test-debug:
	@OPTIMIZE=0 $(REBAR) eunit

publish: docs clean
	$(REBAR) hex $(if $(replace),publish --replace,cut)

tar:
	@rm -f $(TARBALL).tgz; \
	cd ..; \
    tar zcf $(TARBALL).tgz --exclude="core*" --exclude="erl_crash.dump" \
		--exclude="*.tgz" --exclude="*.swp" --exclude="c_src" \
		--exclude="Makefile" --exclude="rebar.*" --exclude="*.mk" \
		--exclude="*.o" --exclude="_build" --exclude=".git*" $(PROJECT) && \
		mv $(TARBALL).tgz $(PROJECT)/ && echo "Created $(TARBALL).tgz"

dialyzer: build.plt
	$(DIALYZER) -nn --plt $< ebin

build.plt:
	$(DIALYZER) -q --build_plt --apps erts kernel stdlib --output_plt $@
