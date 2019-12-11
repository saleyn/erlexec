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

.PHONY : all clean test docs doc clean-docs github-docs dialyzer

all:
	@$(REBAR) compile

clean:
	@$(REBAR) $@

path:
	@echo $(shell $(REBAR) $@)

docs: doc ebin clean-docs
	@$(REBAR) edoc skip_deps=true

doc ebin:
	mkdir -p $@

test:
	@$(REBAR) eunit

publish:
	$(REBAR) hex cut

clean-docs:
	rm -f doc/*.{css,html,png} doc/edoc-info

github-docs: VSN=$(shell git describe --always --tags --abbrev=1 | sed 's/^v//')
github-docs:
	@if git branch | grep -q gh-pages ; then \
		git checkout gh-pages; \
	else \
		git checkout -b gh-pages; \
	fi
	rm -f rebar.lock
	git checkout master -- src include
	git checkout master -- Makefile
	echo '{edoc_opts, [{overview, "src/overview.edoc"}, {def, {vsn, "$(VSN)"}}]}.' > rebar.config
	make docs
	mv doc/*.* .
	make clean
	rm -fr src c_src include Makefile erl_crash.dump priv rebar.* README* _build ebin doc
	@FILES=`git st -uall --porcelain | sed -n '/^?? [A-Za-z0-9]/{s/?? //p}'`; \
	for f in $$FILES ; do \
		echo "Adding $$f"; git add $$f; \
	done
	@sh -c "ret=0; set +e; \
		if   git commit -a --amend -m 'Documentation updated'; \
		then git push origin +gh-pages; echo 'Pushed gh-pages to origin'; \
		else ret=1; git reset --hard; \
		fi; \
		set -e; git checkout master && echo 'Switched to master'; exit $$ret"

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
