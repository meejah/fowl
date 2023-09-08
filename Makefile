.PHONY: ping

pin:
	pip-compile --upgrade --allow-unsafe --generate-hashes --resolver=backtracking --output-file requirements-pinned.txt

release: pin
	python update-version.py
	hatchling build
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fowl-`git describe --abbrev=0`-py3-none-any.whl
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fowl-`git describe --abbrev=0`.tar.gz

undo-release:
	-ls dist/fowl-`git describe --abbrev=0`*
	-rm dist/fowl-`git describe --abbrev=0`*
	git tag -d `git describe --abbrev=0`

release-upload:
	@ls dist/fowl-`git describe --abbrev=0`*
	twine upload dist/fowl-`git describe --abbrev=0`*
