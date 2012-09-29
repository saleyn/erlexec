# See LICENSE for licensing information.

PROJECT = erlexec

DIALYZER = dialyzer
REBAR = rebar

all:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

docs: all clean-docs
	@$(REBAR) doc skip_deps=true

clean-docs:
	rm -f doc/*.{css,html,png} doc/edoc-info

gitdocs:
	git checkout gh-pages
	git checkout master src
	make docs
	git rm -fr src
	mv doc/* .
	rmdir doc

	ret=0; set +e; \
	if git commit -a; then ; git push origin; else ; ret=1; git reset --hard; fi; \
	set -e; git co master

