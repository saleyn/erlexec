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

github-docs:
	git checkout gh-pages
	git checkout master src include c_src Makefile vsn.mk rebar.*
	make docs
	make clean
	rm -fr ebin src include c_src Makefile priv erl_crash.dump vsn.mk rebar.*
	mv doc/* .
	rmdir doc
	sh -c "ret=0; set +e; \
		if git commit -a; then git push origin; else ret=1; exit $$ret; git reset --hard; fi; \
		set -e; git checkout master; exit $$ret"

