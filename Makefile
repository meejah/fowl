

release:
	hatch build
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fow-`git describe --abbrev=0`-py3-none-any.whl
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fow-`git describe --abbrev=0`.tar.gz


release-upload:
	@ls dist/fow-`git describe --abbrev=0`*
	twine upload dist/fow-`git describe --abbrev=0`*
