
Fowl Releases
=============

Stability: this is still a young project, all APIs should be considered unstable.
That said, ``fowld`` input and output is intended to be stable and compatible.

Integration with other programs should use ``fowld`` exclusively.


Unreleased
----------

* (Put new changelog items here)
* Add --version option to fowl and fowld
* Do not fragment on Noise limits; wormhole does this
* Keep closed streams around for a few seconds so
  user can see them and their summary
* Amazing new ANSI-art logo from littlebitspace
* Add --no-logo option to fowl (to hide cool new logo)


25.7.0: July 31, 2025
---------------------

* Cool new ASCII-art / terminal visualization of activity (via "rich")
* Nice error if user gives zero options
* Fix "fowl --readme" and pkg_resources deprecation (#78)
* Massive refactoring of internal APIs, philosophy and specifiers.
  The biggest visible change from this is using "named" services with peer-specified ports.
  There is now a usable API if you're using Python and Twisted already.


25.4.0: April 10, 2025
----------------------

* Allow for non-local addresses: for both listening interfaces and
  connect endpoints, non-local addresses may be specified in a manner
  similar to "ssh -L" or "ssh -R" arguments. See #37:
  https://github.com/meejah/fowl/issues/37
* Fix up some fallout from refactoring
* Enable "remote" command in --interactive
* Proper error-message rendering
* Allow whitelisting only specific connect/listen endpoints.


24.3.1: March 1, 2024
---------------------

* Upgrade dependencies (msgpack, twisted)


24.3.0: March 1, 2024
---------------------

* Simplify ``fowl`` to have no sub-commands
* One side runs ``fowl``, the other one runs ``fowl 1-foo-bar``
* More complete and accurate documentation


24.2.0: February 27, 2024
-------------------------

* Extensive refactoring
* ``fowld`` for machines
* ``fowl`` (with ``tui``, ``accept``, ``invite`` subcommands) for humans
* Lots more unit- and integration- tests written


23.10.2: October 18, 2023
-------------------------

* Initial release, for gathering feedback
