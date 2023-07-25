
Developing FOW
==============

Follow the installation instructions in README.rst using the editable variation::

    ./venv/bin/pip install --editable .

Additionally, install the development dependencies::

    ./venv/bin/pip install --editable .[test]


Running the Tests
-----------------

The integration tests use `pytest <>`_ and exercise the ``fow`` command-line program directly.

A pytest Fixture instantiates a local Magic Wormhole "Mailbox Server" running on port 4000.

To run the suite::

    ./venv/bin/python -m pytest -s -v integration/

To collect coverage::

    ./venv/bin/python -m pytest --cov=fow -s -v integration/
