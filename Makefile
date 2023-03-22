

release:
	python update-version.py
	hatch build
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fow-`git describe --abbrev=0`-py3-none-any.whl
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fow-`git describe --abbrev=0`.tar.gz

undo-release:
	@ls dist/`git describe --abbrev=0`*
	-rm dist/`git describe --abbrev=0`*
	git tag -d `git describe --abbrev=0`


release-upload:
	@ls dist/fow-`git describe --abbrev=0`*
	twine upload dist/fow-`git describe --abbrev=0`*
