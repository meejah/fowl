
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


Future Plans
------------

If you are interested in advancing new features or existing issues with ``fowl`` and related magic-wormhole things, **please get in touch**:

* Meejah is very often in ``#python`` on the Libera IRC network.
* File an issue on GitHub


Specific Future Plans
~~~~~~~~~~~~~~~~~~~~~

Things that we definitely want to do (naming is hard, so those subject to change).

``fowld`` is the lowest-level tool. It continues to speak a protocol on stdin/stdout and has minimal CLI options.

``fowl`` is the main, human-friendly CLI. It could have a ``--daemon`` option to speak to the above -- otherwise, it runs a ``fowl-daemon`` subprocess itself. Care must be taken, then, that the options make sense as either "one-shot" or not. For example, a ``--listen 80`` option to open a local listener (that forward to remote port 80) is fine -- if there's a ``--daemon`` option then it adds that port to the running daemon; otherwise, it starts one and immediately adds that port. Of course, some commands may simply not make sense for the daemon (or not-daemon) cases, but I think the overlaps will be considerable -- so that's a reason to reject splitting this command.



Concrete Use Cases
~~~~~~~~~~~~~~~~~~

tty-share: ability to share tty-share instances over wormhole. One host, one or many clients.

ssh: use fowl to interconnect my devices which do not have a public IP and some of them are constantly on the move

wizard-gardens: See https://meejah.ca/blog/wizard-gardens-vision .. ability to run arbitary glue/plugin code to set up and run various "self-hostable" network applications (a general case of the two above use-cases).
