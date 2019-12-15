import datetime
import sys
import typing

try:
	import pwd
except ModuleNotFoundError:
	pwd = None

try:
	import grp
except ModuleNotFoundError:
	grp = None

import click
import stat
import tabulate

from ksf.ar_generic import ArGeneric
from ksf.ar_bsd import ArBsd
from ksf.ar_sysv import ArSysv
from ksf.ar_gnu_thin import ArGnuThin

tabulate.PRESERVE_WHITESPACE = True


AR_FORMATS = {
	"generic": ArGeneric,
	"bsd": ArBsd,
	"sysv": ArSysv,
	"gnu_thin": ArGnuThin,
}


def format_name(name: bytes, encoding: str) -> str:
	try:
		return repr(name.decode(encoding))
	except UnicodeDecodeError:
		return repr(name)


def format_timestamp(timestamp: typing.Optional[int]) -> typing.Optional[str]:
	if timestamp is None:
		return None
	else:
		return str(datetime.datetime.utcfromtimestamp(timestamp))


def lookup_user(uid: int) -> typing.Optional[pwd.struct_passwd]:
	if pwd is None:
		return None
	
	try:
		return pwd.getpwuid(uid)
	except KeyError:
		return None


def format_uid(uid: typing.Optional[int]) -> typing.Optional[str]:
	if uid is None:
		return None
	else:
		user = lookup_user(uid)
		name = "?" if user is None else user.pw_name
		return f"{name} ({uid})"


def lookup_group(gid: int) -> typing.Optional[grp.struct_group]:
	if grp is None:
		return None
	
	try:
		return grp.getgrgid(gid)
	except KeyError:
		return None


def format_gid(gid: typing.Optional[int]) -> typing.Optional[str]:
	if gid is None:
		return None
	else:
		group = lookup_group(gid)
		name = "?" if group is None else group.gr_name
		return f"{name} ({gid})"


def format_mode(mode: typing.Optional[int]) -> typing.Optional[str]:
	if mode is None:
		return None
	else:
		return f"{stat.filemode(mode)} ({mode:>08o})"


def format_size(size: typing.Optional[int]) -> typing.Optional[str]:
	if size is None:
		return None
	else:
		return str(size)


def read_archive_members(f: typing.BinaryIO, *, format: str) -> typing.Any:
	return AR_FORMATS[format].from_io(f).members


@click.group()
def main() -> None:
	pass


@main.command(name="list")
@click.argument("archive", type=click.File("rb"))
@click.option("--format", type=click.Choice(AR_FORMATS.keys()), required=True, help="Which variant of the ar format is used by the archive.")
@click.option("--name-encoding", type=str, default=sys.getfilesystemencoding(), help="The encoding used to decode archive member names.")
def do_list(
	archive: typing.BinaryIO,
	*,
	format: str,
	name_encoding: str,
) -> None:
	"""List the members of an archive."""
	
	rows = []
	for member in read_archive_members(archive, format=format):
		rows.append([
			format_name(member.name, name_encoding),
			format_size(member.size),
			format_timestamp(member.metadata.modified_timestamp),
			format_uid(member.metadata.user_id),
			format_gid(member.metadata.group_id),
			format_mode(member.metadata.mode),
		])
	print(tabulate.tabulate(
		rows,
		showindex="always",
		headers=["#", "Name", "Size", "Modified", "User", "Group", "Mode"],
		stralign="left",
		disable_numparse=True,
		missingval="-",
	))


@main.command("read")
@click.argument("archive", type=click.File("rb"))
@click.argument("member_name", type=str)
@click.option("--format", type=click.Choice(AR_FORMATS.keys()), required=True, help="Which variant of the ar format is used by the archive.")
@click.option("--name-encoding", type=str, default=sys.getfilesystemencoding(), help="The encoding used to decode archive member names.")
@click.option("-o", "--output-file", type=click.File("wb"), default="-", help="The file to which to output the member data.")
def do_extract(
	archive: typing.BinaryIO,
	member_name: str,
	*,
	format: str,
	name_encoding: str,
	output_file: typing.Optional[typing.BinaryIO],
) -> None:
	"""Read the data of an archive member."""
	
	encoded_name = member_name.encode(name_encoding)
	for member in read_archive_members(archive, format=format):
		if member.name == encoded_name:
			if member.data is None:
				assert format == "gnu_thin"
				print(f"{member_name!r} is a thin archive member, its contents are not stored in the archive", file=sys.stderr)
				sys.exit(1)
			
			output_file.write(member.data)
			break
	else:
		print(f"Could not find a member named {member_name!r}", file=sys.stderr)


if __name__ == "__main__":
	main()
