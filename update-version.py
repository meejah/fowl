#
# this updates the (tagged) version of the software
#
# we use YY.MM.<counter> so the process to update the version is to
# take today's date, start with counter at 0 and increment counter
# until we _don't_ find a tag like that.
#
# e.g. v22.1.0 is the first release in January, 2022 and v22.1.1 is
# the second release in January, 2022, etc.
#
# Any "options" are hard-coded in here (e.g. the GnuPG key to use)
#

author = "meejah <meejah@meejah.ca>"


import sys
import time
import itertools
import subprocess
from datetime import datetime
import pysequoia

from dulwich.repo import Repo
from dulwich.porcelain import (
    tag_list,
    tag_create,
    status,
)

from twisted.internet.task import (
    react,
)
from twisted.internet.defer import (
    ensureDeferred,
)


def existing_tags(git):
    versions = list(v.decode("utf8") for v in tag_list(git))
    return versions


def create_new_version(git):
    now = datetime.now()
    versions = existing_tags(git)

    for counter in itertools.count():
        version = "{}.{}.{}".format(now.year - 2000, now.month, counter)
        if version not in versions:
            return version


async def main(reactor):
    git = Repo(".")

    # including untracked files can be very slow (if there are lots,
    # like in virtualenvs) and we don't care anyway
    st = status(git, untracked_files="no")
    if any(st.staged.values()) or st.unstaged:
        print("unclean checkout; aborting")
        raise SystemExit(1)

    v = create_new_version(git)
    if "--no-tag" in sys.argv:
        print(v)
        return

    subprocess.check_call(["hatch", "version", str(v)])
    subprocess.check_call(["git", "add", "-u"])
    subprocess.check_call(["git", "commit", "-m", "update version"])

    print("Existing tags: {}".format(" ".join(existing_tags(git))))
    print("New tag will be {}".format(v))

    # the "tag time" is seconds from the epoch .. we quantize these to
    # the start of the day in question, in UTC.
    now = datetime.now()
    s = now.utctimetuple()
    ts = int(
        time.mktime(
            time.struct_time((s.tm_year, s.tm_mon, s.tm_mday, 0, 0, 0, 0, s.tm_yday, 0))
        )
    )
    keyid = "9D5A2BD5688ECB889DEBCD3FC2602803128069A7"
    args = ["sq", "key", "export", "--cert", keyid]
    certdata = subprocess.check_output(args)
    cert = pysequoia.Cert.from_bytes(certdata)
    passphrase = input("passphrase:")
    signer = cert.secrets.signer(passphrase)

    tag_create(
        repo=git,
        tag=v.encode("utf8"),
        author=author.encode("utf8"),
        message="Release {}".format(v).encode("utf8"),
        annotated=True,
        objectish=b"HEAD",
        sign=signer,
        tag_time=ts,
        tag_timezone=0,
    )

    print("Tag created locally, it is not pushed")
    print("To push it run something like:")
    print("   git push origin {}".format(v))


if __name__ == "__main__":
    react(lambda r: ensureDeferred(main(r)))
