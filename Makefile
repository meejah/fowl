.PHONY: ping

pin:
	pip-compile --upgrade --allow-unsafe --generate-hashes --resolver=backtracking --output-file requirements-pinned.txt

release: pin
	python update-version.py
	hatch build
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fow-`git describe --abbrev=0`-py3-none-any.whl
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fow-`git describe --abbrev=0`.tar.gz

undo-release:
	@ls dist/fow-`git describe --abbrev=0`*
	-rm dist/fow-`git describe --abbrev=0`*
	git tag -d `git describe --abbrev=0`

release-upload:
	@ls dist/fow-`git describe --abbrev=0`*
	twine upload dist/fow-`git describe --abbrev=0`*
