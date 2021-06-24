import datetime
import io
import os
import shutil
import sys
import typing
import zipfile

import click
import tabulate

from ksf.dos_datetime_backwards import DosDatetimeBackwards
from ksf.install_shield_3_sfx_tail import InstallShield3SfxTail
from ksf.microsoft_pe import MicrosoftPe

tabulate.PRESERVE_WHITESPACE = True


def find_tail_start(installer: typing.BinaryIO) -> int:
	mz_lookahead = installer.read(2)
	installer.seek(0)
	if mz_lookahead != b"MZ":
		# Not an EXE file - assuming that it's just the tail with the EXE already removed.
		return 0
	
	exe = MicrosoftPe.from_io(installer)
	return max(section.pointer_to_raw_data + section.size_of_raw_data for section in exe.pe.sections)

def parse_sfx(installer: typing.BinaryIO, *, offset: typing.Optional[int]) -> InstallShield3SfxTail:
	if offset is None:
		# If not seekable (i. e. reading from stdin),
		# assume that the stream is already positioned at the tail.
		if installer.seekable():
			installer.seek(find_tail_start(installer))
	else:
		installer.seek(offset)
	
	return InstallShield3SfxTail.from_io(installer)


# Stolen from http://kannegieser.net/veit/quelle/stix_src.arj, STSFX.PAS

KEY = b"\xb3\xf2\xea\x1f\xaa\x27\x66\x13"

def ror8(byte: int, rot: int) -> int:
	return (byte >> (rot & 7) | (byte << 8) >> (rot & 7)) & 0xff

def decrypt_path(data: bytes) -> bytes:
	ret = bytearray(len(data))
	for i, byte in enumerate(data):
		ret[i] = ror8(byte ^ KEY[7-(i%8)], 7-(i%8)) ^ KEY[i%8]
	return ret


def format_name_technical(name: bytes, encoding: str) -> str:
	try:
		return repr(name.decode(encoding))
	except UnicodeDecodeError:
		return repr(name)

def _escape_name_char(c):
	if c.isprintable():
		return c
	else:
		cp = chr(c)
		if 0xdc80 <= cp < 0xdd00:
			# from surrogateescape
			return f"[x{cp - 0xdc00:>02x}]"
		else:
			return f"[U+{cp:>04x}]"

def format_name_readable(name: str) -> str:
	return "".join(_escape_name_char(c) for c in name)

def format_dos_datetime(dos: DosDatetimeBackwards) -> str:
	return f"{dos.date.padded_year}-{dos.date.padded_month}-{dos.date.padded_day} {dos.time.padded_hour}:{dos.time.padded_minute}:{dos.time.padded_second}"


def do_list_technical(parsed: InstallShield3SfxTail, *, name_encoding: str) -> None:
	rows = []
	for file in parsed.files:
		rows.append([
			format_name_technical(decrypt_path(file.path_encrypted), name_encoding),
			str(file.len_data),
			format_dos_datetime(file.modified),
		])
	print(tabulate.tabulate(
		rows,
		showindex="always",
		headers=["#", "Path", "Size", "Modified"],
		stralign="left",
		disable_numparse=True,
		missingval="-",
	))

def do_list_readable(parsed: InstallShield3SfxTail, *, name_encoding: str) -> None:
	rows = []
	for file in parsed.files:
		rows.append([
			format_name_readable(decrypt_path(file.path_encrypted).decode(name_encoding, errors="surrogateescape")),
			str(file.len_data),
			format_dos_datetime(file.modified),
		])
	print(tabulate.tabulate(
		rows,
		headers=["Path", "Size", "Modified"],
		stralign="left",
		disable_numparse=True,
		missingval="-",
	))


def check_open_zip_file(zip_stream: typing.BinaryIO, path: str) -> typing.Optional[zipfile.ZipFile]:
	try:
		return zipfile.ZipFile(zip_stream)
	except zipfile.BadZipFile:
		print(f"Warning: Data for path {path!r} is not a valid ZIP file.", file=sys.stderr)
		return None

def find_single_file_in_zip(zf: zipfile.ZipFile, path: str) -> typing.Optional[zipfile.ZipInfo]:
	infos = zf.infolist()
	if not infos:
		print(f"Warning: ZIP data for path {path!r} doesn't contain any files.", file=sys.stderr)
		return None
	elif len(infos) > 1:
		print(f"Warning: ZIP data for path {path!r} contains more than one file.", file=sys.stderr)
		return None
	
	(info,) = infos
	split_path = path.split("\\")
	if info.filename != split_path[-1]:
		print(f"Warning: ZIP data for path {path!r} contains a differently named file {info.filename!r}.", file=sys.stderr)
		return None
	
	return info

def extract_from_zip(zf: zipfile.ZipFile, info: zipfile.ZipInfo, output_file: typing.BinaryIO) -> int:
	# We extract the file manually instead of using the extract method,
	# so that we can extract to any file name or stdout
	# (extract only takes a directory and automatically appends the archive member name)
	# and so that we can restore the modification timestamp if possible
	# (which extract doesn't do for some reason).
	with zf.open(info, "r") as fin:
		shutil.copyfileobj(fin, output_file)
	return datetime.datetime(*info.date_time).timestamp()

def timestamp_from_dos_datetime(dos: DosDatetimeBackwards) -> int:
	return datetime.datetime(dos.date.year, dos.date.month, dos.date.day, dos.time.hour, dos.time.minute, dos.time.second).timestamp()

def extract_single_file(file: InstallShield3SfxTail.File, output_file: typing.BinaryIO) -> int:
	output_file.write(file.data)
	return timestamp_from_dos_datetime(file.modified)

def extract_single_file_unzip(file: InstallShield3SfxTail.File, path: str, output_file: typing.BinaryIO) -> typing.Optional[int]:
	zf = check_open_zip_file(io.BytesIO(file.data), path)
	if zf is not None:
		with zf:
			info = find_single_file_in_zip(zf, path)
			if info is not None:
				return extract_from_zip(zf, info, output_file)
	
	print(f"Error: File data not in expected ZIP format.", file=sys.stderr)
	print(f"Note: Use the --no-unzip option to read the data without unzipping.", file=sys.stderr)
	return None

def do_read_internal(file: InstallShield3SfxTail.File, path: str, output_file: typing.BinaryIO, *, unzip: bool) -> typing.Optional[int]:
	if unzip:
		return extract_single_file_unzip(file, path, output_file)
	else:
		return extract_single_file(file, output_file)


@click.group()
def main() -> None:
	pass


@main.command(name="list")
@click.argument("installer", type=click.File("rb"))
@click.option("--technical/--no-technical", help="Display more technical details in a less readable format.")
@click.option("--name-encoding", type=str, default="ascii", help="The encoding used to decode path names in the installer.")
@click.option("--offset", type=int, help="Absolute byte offset where the tail starts. By default the script tries to find the tail automatically, so normally you do not need to manually pass the tail offset.")
def do_list(
	installer: typing.BinaryIO,
	*,
	technical: bool,
	name_encoding: str,
	offset: typing.Optional[int],
) -> None:
	"""List the files stored in an installer."""
	
	parsed = parse_sfx(installer, offset=offset)
	
	if technical:
		do_list_technical(parsed, name_encoding=name_encoding)
	else:
		do_list_readable(parsed, name_encoding=name_encoding)


@main.command(name="read")
@click.argument("installer", type=click.File("rb"))
@click.argument("path", type=str)
@click.option("-o", "--output-file", type=click.Path(allow_dash=True), default="-", help="The path to which to write the extracted file, or - to extract to stdout.")
@click.option("--unzip/--no-unzip", default=True, help="Whether to try automatically unzipping the file data. Normally, each file is stored as a ZIP archive containing the actual file.")
@click.option("--name-encoding", type=str, default="ascii", help="The encoding used to decode path names in the installer.")
@click.option("--offset", type=int, help="Absolute byte offset where the tail starts. By default the script tries to find the tail automatically, so normally you do not need to manually pass the tail offset.")
def do_read(
	installer: typing.BinaryIO,
	path: str,
	*,
	output_file: typing.Union[str, bytes, os.PathLike],
	unzip: bool,
	name_encoding: str,
	offset: typing.Optional[int],
) -> None:
	"""Read the contents of a single file stored in an installer."""
	
	parsed = parse_sfx(installer, offset=offset)
	
	encoded_path = path.encode(name_encoding)
	for file in parsed.files:
		if decrypt_path(file.path_encrypted) == encoded_path:
			if os.fspath(output_file) in {"-", b"-"}:
				timestamp = do_read_internal(file, path, click.get_binary_stream("stdout"), None, unzip=unzip)
			else:
				with open(output_file, "wb") as fout:
					timestamp = do_read_internal(file, path, fout, unzip=unzip)
				if timestamp is not None:
					os.utime(output_file, (timestamp, timestamp))
			
			if timestamp is None:
				sys.exit(1)
			
			break
	else:
		print(f"Could not find a file with path {path!r}", file=sys.stderr)
		sys.exit(1)


@main.command(name="extract")
@click.argument("installer", type=click.Path(allow_dash=True, path_type=str))
@click.option("-o", "--output-dir", type=click.Path(path_type=str), default=None, help="The directory into which to extract the files. Defaults to a subdiretory in the current directory, named after the installer file.")
@click.option("-v", "--verbose/--no-verbose", help="List files to stdout as they are extracted.")
@click.option("--unzip/--no-unzip", default=True, help="Whether to try automatically unzipping the file data. Normally, each file is stored as a ZIP archive containing the actual file.")
@click.option("--name-encoding", type=str, default="ascii", help="The encoding used to decode path names in the installer.")
@click.option("--offset", type=int, help="Absolute byte offset where the tail starts. By default the script tries to find the tail automatically, so normally you do not need to manually pass the tail offset.")
def do_extract(
	installer: str,
	*,
	output_dir: typing.Optional[str],
	verbose: bool,
	unzip: bool,
	name_encoding: str,
	offset: typing.Optional[int],
) -> None:
	"""Extract all files from an installer,
	including the directory structure."""
	
	if output_dir is None:
		output_dir = os.path.basename(installer) + ".extracted"
	
	with click.open_file(installer, "rb") as installerf:
		parsed = parse_sfx(installerf, offset=offset)
	
	for file in parsed.files:
		path = decrypt_path(file.path_encrypted).decode(name_encoding)
		if unzip:
			zf = check_open_zip_file(io.BytesIO(file.data), path)
			if zf is None:
				raw_output_path = path
			else:
				with zf:
					info = find_single_file_in_zip(zf, path)
					if info is None:
						raw_output_path = path + ".zip"
					else:
						output_file = os.path.join(output_dir, *path.split("\\"))
						if verbose:
							print(f"Extracting: {format_name_readable(path)} ({len(file.data)} bytes zipped) -> {click.format_filename(output_file)}")
						os.makedirs(os.path.dirname(output_file), exist_ok=True)
						with open(output_file, "wb") as fout:
							timestamp = extract_from_zip(zf, info, fout)
						os.utime(output_file, (timestamp, timestamp))
						continue
			
			print(f"Warning: Extracting {path!r} to {raw_output_path!r} without unzipping.", file=sys.stderr)
		else:
			raw_output_path = path
		
		output_file = os.path.join(output_dir, *raw_output_path.split("\\"))
		if verbose:
			print(f"Extracting: {format_name_readable(path)} ({len(file.data)} bytes) -> {click.format_filename(output_file)}")
		os.makedirs(os.path.dirname(output_file), exist_ok=True)
		with open(output_file, "wb") as fout:
			timestamp = extract_single_file(file, fout)
		os.utime(output_file, (timestamp, timestamp))


if __name__ == "__main__":
	main()
