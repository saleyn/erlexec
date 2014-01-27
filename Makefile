# See LICENSE for licensing information.

VSN     = $(shell git describe --always --tags --abbrev=0 | sed 's/^v//')
PROJECT = $(notdir $(PWD))
TARBALL = $(PROJECT)-$(VSN)

DIALYZER = dialyzer
REBAR = rebar

.PHONY : all clean test docs doc clean-docs github-docs

all:
	@$(REBAR) compile

clean:
	@$(REBAR) clean
	@rm -fr ebin doc

docs: doc ebin clean-docs
	@$(REBAR) doc skip_deps=true

doc ebin:
	mkdir -p $@

test:
	@$(REBAR) eunit

clean-docs:
	rm -f doc/*.{css,html,png} doc/edoc-info

github-docs:
	@if git branch | grep -q gh-pages ; then \
		git checkout gh-pages; \
	else \
		git checkout -b gh-pages; \
	fi
	git checkout master src include Makefile rebar.*
	make docs
	mv doc/*.* .
	make clean
	rm -fr src c_src include Makefile erl_crash.dump priv rebar.* README*
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
		--exclude="*.o" --exclude=".git*" $(PROJECT) && \
		mv $(TARBALL).tgz $(PROJECT)/ && echo "Created $(TARBALL).tgz"
