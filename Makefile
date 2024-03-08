.PHONY: pin release

pin:
	pip-compile --upgrade --allow-unsafe --generate-hashes --resolver=backtracking --output-file requirements-pinned.txt
	git add -u
	git commit -m "upgrade pins"

test:
	coverage erase
	coverage run --parallel -m pytest --disable-warnings -sv src/fowl
	coverage run --parallel -m pytest -v integration/
	coverage combine
	cuv graph

#release: pin
release:
	python update-version.py
	hatch version `git tag --sort -v:refname | head -1`
	git add -u
	git commit -m "update version"
	hatchling build
	twine check dist/fowl-`git describe --abbrev=0`-py3-none-any.whl
	twine check dist/fowl-`git describe --abbrev=0`.tar.gz
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fowl-`git describe --abbrev=0`-py3-none-any.whl
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/fowl-`git describe --abbrev=0`.tar.gz

undo-release:
	-ls dist/fowl-`git describe --abbrev=0`*
	-rm dist/fowl-`git describe --abbrev=0`*
	git tag -d `git describe --abbrev=0`

release-upload:
	@ls dist/fowl-`git describe --abbrev=0`*
	twine upload --username __token__ --password `cat PRIVATE-release-token` dist/fowl-`git describe --abbrev=0`*
	git push github `git describe --abbrev=0`

wg.png: wizard-garden-app-interaction.seq
	# pip install seqdiag 'pillow<10'
	seqdiag -T png --no-transparency -o wg.png wizard-garden-app-interaction.seq
