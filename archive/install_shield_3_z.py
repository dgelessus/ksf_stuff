import datetime
import os
import sys
import typing
import zlib

import click
import tabulate

from ksf.dos_datetime_backwards import DosDatetimeBackwards
from ksf.install_shield_3_z import InstallShield3Z

tabulate.PRESERVE_WHITESPACE = True


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

def format_name_readable(name: bytes, encoding: str) -> str:
	return "".join(_escape_name_char(c) for c in name.decode(encoding, errors="surrogateescape"))

def format_dir_path_readable(path: bytes, encoding: str) -> str:
	if path:
		return format_name_readable(path, encoding)
	else:
		return "[top-level dir]"

def join_dir_file_name(dir: bytes, name: bytes) -> bytes:
	if dir:
		return dir + b"\\" + name
	else:
		return name

def format_dir_file_count(count: int) -> str:
	if count == 0:
		return "empty dir"
	elif count == 1:
		return "1 file"
	else:
		return f"{count} files"

def format_sizes(compressed: int, uncompressed: int) -> str:
	if compressed == uncompressed:
		return str(uncompressed)
	else:
		return f"{uncompressed} ({compressed} compr.)"

def format_dos_datetime(dos: DosDatetimeBackwards) -> str:
	return f"{dos.date.padded_year}-{dos.date.padded_month}-{dos.date.padded_day} {dos.time.padded_hour}:{dos.time.padded_minute}:{dos.time.padded_second}"

def format_attributes_technical(attributes: int) -> str:
	if attributes < 0x100:
		res = ""
		for c in "RHSVDA67":
			if attributes & 1:
				res += c
			else:
				res += "."
			attributes >>= 1
		return res
	else:
		return f"0x{attributes:>08x}"

def format_attributes_readable(attributes: int) -> typing.Optional[str]:
	res = ""
	if attributes >> 0 & 1:
		res += "R"
	if attributes >> 1 & 1:
		res += "H"
	if attributes >> 2 & 1:
		res += "S"
	if attributes >> 5 & 1:
		res += "A"
	return res or None

def format_version(version: InstallShield3Z.Version) -> typing.Optional[str]:
	return f"{version.major}.{version.minor}.{version.build}.{version.private}"


def show_and_check_sums(parsed: InstallShield3Z) -> None:
	header = parsed.header
	
	total_compressed = 0
	total_uncompressed = 0
	for file in parsed.toc_files:
		total_compressed += file.len_data_compressed
		total_uncompressed += file.len_data_uncompressed
	
	print(f"Total size of all files: {total_compressed} bytes compressed, {total_uncompressed} bytes uncompressed")
	
	if header.total_uncompressed_size != total_uncompressed:
		print(f"Warning: total uncompressed size mismatch! Expected {header.total_uncompressed_size} bytes.", file=sys.stderr)
	
	if header.is_split or header.is_split_contiguous:
		# TODO Are modulo 253 checksums actually used?
		checksum1 = total_compressed % 251
		checksum2 = total_compressed % 253
		if header.checksum == checksum1:
			print(f"Checksum OK (modulo 251): 0x{header.checksum:>02x}")
		elif header.checksum == checksum2:
			print(f"Checksum OK (modulo 253): 0x{header.checksum:>02x}")
		else:
			print(f"Warning: checksum mismatch! Expected 0x{header.checksum:>02x}, but actual value is 0x{checksum1:>02x} (modulo 251) or 0x{checksum2:>02x} (modulo 253).", file=sys.stderr)


def do_list_technical(parsed: InstallShield3Z, *, name_encoding: str) -> None:
	rows_dirs = []
	for dir in parsed.toc_directories:
		rows_dirs.append([
			format_name_technical(dir.path, name_encoding),
			str(dir.num_files),
		])
	print(tabulate.tabulate(
		rows_dirs,
		showindex="always",
		headers=["#", "Directory", "# files"],
		stralign="left",
		disable_numparse=True,
		missingval="-",
	))
	
	print()
	
	rows_files = []
	for file in parsed.toc_files:
		flags = []
		if file.internal_flag:
			flags.append("internal deleted flag")
		if file.has_version:
			flags.append("has version")
		if file.is_split:
			flags.append("split")
		rows_files.append([
			str(file.directory_index),
			format_name_technical(file.directory.path, name_encoding),
			format_name_technical(file.name, name_encoding),
			str(file.len_data_uncompressed),
			str(file.len_data_compressed),
			"Store" if file.is_uncompressed else "Implode",
			format_dos_datetime(file.modified),
			format_attributes_technical(file.attributes),
			f"{file.start_part}..{file.end_part}",
			format_version(file.version),
			", ".join(flags) if flags else None,
		])
	print(tabulate.tabulate(
		rows_files,
		showindex="always",
		headers=["#", "Dir. #", "Directory", "Name", "Size", "Compressed", "Method", "Modified", "Attrs", "Parts", "Version", "Flags"],
		stralign="left",
		disable_numparse=True,
		missingval="-",
	))

def do_list_readable(parsed: InstallShield3Z, *, name_encoding: str) -> None:
	files_by_dir = [[] for _ in parsed.toc_directories]
	for file in parsed.toc_files:
		files_by_dir[file.directory_index].append(file)
	
	rows = []
	
	for i, dir in sorted(enumerate(parsed.toc_directories), key=lambda x: x[1].path):
		files = files_by_dir[i]
		assert len(files) == dir.num_files
		rows.append([
			format_dir_path_readable(dir.path, name_encoding),
			format_dir_file_count(dir.num_files),
			None,
			None,
			"D",
			None,
		])
		
		for file in sorted(files, key=lambda f: f.name):
			rows.append([
				format_name_readable(join_dir_file_name(dir.path, file.name), name_encoding),
				str(file.len_data_uncompressed),
				str(file.len_data_compressed),
				format_dos_datetime(file.modified),
				format_attributes_readable(file.attributes),
				format_version(file.version),
			])
	
	print(tabulate.tabulate(
		rows,
		headers=["Path", "Size", "Compressed", "Modified", "Attrs", "Version"],
		stralign="left",
		disable_numparse=True,
		missingval="-",
	))


def timestamp_from_dos_datetime(dos: DosDatetimeBackwards) -> int:
	return datetime.datetime(dos.date.year, dos.date.month, dos.date.day, dos.time.hour, dos.time.minute, dos.time.second).timestamp()

def extract_file_data(file: InstallShield3Z.TocFile, output_file: typing.BinaryIO) -> None:
	if not file.is_uncompressed:
		print(f"Error: Reading PKWARE DCL Implode-compressed files is not supported yet.", file=sys.stderr)
		print(f"Note: Use the to-zip subcommand to convert this archive to ZIP format and try extracting it using an unzip program that supports PKWARE DCL Implode compression.", file=sys.stderr)
		sys.exit(1)
	
	output_file.write(file.data_compressed)

def restore_file_metadata(file: InstallShield3Z.TocFile, output_path: typing.Union[str, bytes, os.PathLike]) -> None:
	timestamp = timestamp_from_dos_datetime(file.modified)
	os.utime(output_path, (timestamp, timestamp))
	# There's no good way to restore the file attributes,
	# as Python only exposes POSIX-style attributes/permissions,
	# and even on Windows there's no way to set DOS/Windows-style attributes directly.
	# At best the read-only attribute can be mapped to POSIX permissions,
	# but in practice the attributes usually aren't important anyway.


def pack_dos_time(hour: int, minute: int, second_div_2: int) -> int:
	return hour << 11 | minute << 5 | second_div_2 << 0

def pack_dos_date(year_minus_1980: int, month: int, day: int) -> int:
	return year_minus_1980 << 9 | month << 5 | day << 0

def pack_zip_date_time(dos: DosDatetimeBackwards) -> bytes:
	return (
		pack_dos_time(dos.time.hour, dos.time.minute, dos.time.second_div_2).to_bytes(2, "little")
		+ pack_dos_date(dos.date.year_minus_1980, dos.date.month, dos.date.day).to_bytes(2, "little")
	)


@click.group()
def main() -> None:
	pass


@main.command(name="list")
@click.argument("archive", type=click.File("rb"))
@click.option("--technical/--no-technical", help="Display more technical details in a less readable format.")
@click.option("--name-encoding", type=str, default="ascii", help="The encoding used to decode path names in the archive.")
def do_list(
	archive: typing.BinaryIO,
	*,
	technical: bool,
	name_encoding: str,
) -> None:
	"""List the members of an archive."""
	
	parsed = InstallShield3Z.from_io(archive)
	header = parsed.header
	
	if technical and header.is_extended:
		print("Archive file is in extended (multi-part-capable) format")
	
	if header.is_extended and header.num_parts > 1:
		print(f"This is part {header.part} of a {header.num_parts}-part archive")
		what_this = "part"
	else:
		what_this = "archive"
	
	print(f"This {what_this} contains {header.num_directories} directories and {header.num_files} files")
	print(f"Last modified: " + format_dos_datetime(header.modified))
	print()
	
	if technical:
		print("Archive header technical details:")
		if header.is_split:
			print("Split flag set")
		if header.is_split_contiguous:
			print("Split contiguous flag set")
		print(f"len_archive: {header.len_archive:#x}")
		print(f"start_integral_data: {header.start_integral_data:#x}")
		print(f"end_integral_data: {header.end_integral_data:#x}")
		print(f"ofs_data: {header.ofs_data:#x}")
		print(f"total_uncompressed_size: {header.total_uncompressed_size:#x}")
		print(f"ofs_toc_directories: {header.ofs_toc_directories:#x}")
		print(f"len_toc_directories: {header.len_toc_directories:#x}")
		print(f"=> end of toc_directories: {header.ofs_toc_directories + header.len_toc_directories:#x}")
		print(f"ofs_toc_files: {header.ofs_toc_files:#x}")
		print(f"len_toc_files: {header.len_toc_files:#x}")
		print(f"=> end of toc_files: {header.ofs_toc_files + header.len_toc_files:#x}")
		print(f"checksum: {header.checksum:#x}")
		print(f"password: {header.password:#x}")
		print()
		
		do_list_technical(parsed, name_encoding=name_encoding)
	else:
		do_list_readable(parsed, name_encoding=name_encoding)
	
	print()
	show_and_check_sums(parsed)


@main.command("read")
@click.argument("archive", type=click.File("rb"))
@click.argument("path", type=str)
@click.option("-o", "--output-file", type=click.Path(allow_dash=True), default="-", help="The path to which to write the extracted file, or - to extract to stdout.")
@click.option("--name-encoding", type=str, default="ascii", help="The encoding used to decode path names in the archive.")
def do_read(
	archive: typing.BinaryIO,
	path: str,
	*,
	name_encoding: str,
	output_file: typing.Union[str, bytes, os.PathLike],
) -> None:
	"""Read the data of an archive member."""
	
	# If the path doesn't contain any backslashes,
	# an empty string is returned for dir_path,
	# which happens to be the right value we need in that case.
	dir_path, _, file_name = path.rpartition("\\")
	encoded_dir_path = dir_path.encode(name_encoding)
	encoded_file_name = file_name.encode(name_encoding)
	
	parsed = InstallShield3Z.from_io(archive)
	
	for dir_index, dir in enumerate(parsed.toc_directories):
		if dir.path == encoded_dir_path:
			break
	else:
		if dir_path:
			print(f"Error: Directory {dir_path!r} not found in archive.", file=sys.stderr)
		else:
			print("Error: No top-level directory found in archive.", file=sys.stderr)
			print("Note: To read a file from a subdirectory, use a full path including a directory name.", file=sys.stderr)
		if "/" in member_name:
			print("Note: Use \\ instead of / as the directory separator.", file=sys.stderr)
		sys.exit(1)
	
	for file in parsed.toc_files:
		if file.directory_index == dir_index and file.name == encoded_file_name:
			if os.fspath(output_file) in {"-", b"-"}:
				extract_file_data(file, click.get_binary_stream("stdout"))
			else:
				with open(output_file, "wb") as fout:
					extract_file_data(file, fout)
				restore_file_metadata(file, output_file)
			
			break
	else:
		if dir_path:
			print(f"Error: File {file_name!r} not found in directory {dir_path!r}.", file=sys.stderr)
		else:
			print(f"Error: File {file_name!r} not found in top-level directory.", file=sys.stderr)
			print("Note: To read a file from a subdirectory, use a full path including a directory name.", file=sys.stderr)


@main.command(name="extract")
@click.argument("archive", type=click.Path(allow_dash=True, path_type=str))
@click.option("-o", "--output-dir", type=click.Path(path_type=str), default=None, help="The directory into which to extract the files. Defaults to a subdiretory in the current directory, named after the archive file.")
@click.option("-v", "--verbose/--no-verbose", help="List files to stdout as they are extracted.")
@click.option("--name-encoding", type=str, default="ascii", help="The encoding used to decode path names in the installer.")
def do_extract(
	archive: str,
	*,
	output_dir: typing.Optional[str],
	verbose: bool,
	name_encoding: str,
) -> None:
	"""Extract all files and directories from an archive."""
	
	if output_dir is None:
		output_dir = os.path.basename(archive) + ".extracted"
	
	with click.open_file(archive, "rb") as archivef:
		parsed = InstallShield3Z.from_io(archivef)
		
		dir_paths = []
		for dir in parsed.toc_directories:
			dir_path = os.path.join(output_dir, *dir.path.decode(name_encoding).split("\\"))
			dir_paths.append(dir_path)
			os.makedirs(dir_path, exist_ok=True)
		
		for file in parsed.toc_files:
			file_path_in_archive = join_dir_file_name(file.directory.path, file.name)
			output_path = os.path.join(output_dir, *file_path_in_archive.decode(name_encoding).split("\\"))
			if verbose:
				print(f"Extracting: {format_name_readable(file_path_in_archive, name_encoding)} ({file.len_data_compressed} bytes) -> {click.format_filename(output_path)}")
			with open(output_path, "wb") as fout:
				extract_file_data(file, fout)
			restore_file_metadata(file, output_path)
		
		archive_timestamp = timestamp_from_dos_datetime(parsed.header.modified)
		for dir_path in dir_paths:
			os.utime(dir_path, (archive_timestamp, archive_timestamp))


@main.command(name="to-zip")
@click.argument("archive", type=click.Path(allow_dash=True, path_type=str))
@click.option("-o", "--output-file", type=click.Path(allow_dash=True, path_type=str), default=None, help="The file to which to output the converted ZIP file. Defaults to a file in the current directory, named after the original archive file.")
def do_to_zip(
	archive: str,
	*,
	output_file: typing.Optional[str],
) -> None:
	"""Convert an archive into ZIP format.
	
	This tries to perform only the minimal amount of conversion necessary.
	File/directory names are only adjusted to replace backslashes with slashes -
	no encoding conversion is performed,
	and they are marked in the ZIP file as using a legacy non-UTF-8 encoding.
	The metadata fields for uncompressed size,
	last modified date/time,
	and DOS file attributes are directly copied over and not checked further.
	The file data is not (re)compressed -
	it is copied into the ZIP archive in its original format,
	i. e. either stored uncompressed or with PKWARE DCL Implode compression.
	
	PKWARE DCL Implode compression is technically allowed by the ZIP format,
	but almost no ZIP extractor seems to actually implement it
	(Info-ZIP 6.00, p7zip 16.02, bsdtar 3.5.1, and unstuff 5.2.0.611
	all report that they don't support the compression method).
	This script also has no way to decompress such data,
	so as a result no CRC-32 checksum can be calculated for any files that use this method.
	So even if you find a ZIP extractor that can handle this compression method,
	expect lots of CRC-32 checksum errors for ZIP files generated by this script.
	"""
	
	if output_file is None:
		output_file = os.path.basename(archive) + ".zip"
	
	with click.open_file(archive, "rb") as archivef:
		parsed = InstallShield3Z.from_io(archivef)
		
		with click.open_file(output_file, "wb") as zipf:
			central_directory = b""
			num_central_directory_entries = 0
			
			archive_modified = pack_zip_date_time(parsed.header.modified)
			for dir in parsed.toc_directories:
				if not dir.path:
					# ZIPs don't store the top-level directory explicitly
					continue
				
				local_header_offset = zipf.tell()
				path = dir.path.replace(b"\\", b"/") + b"/"
				
				header_common = b""
				header_common += (20).to_bytes(1, "little") # min. version to extract (2.0, because directory)
				header_common += b"\x00" # attribute format (DOS)
				header_common += b"\x00\x00" # flags (none needed)
				header_common += b"\x00\x00" # compression method (stored)
				header_common += archive_modified # modified
				header_common += b"\x00\x00\x00\x00" # CRC-32
				header_common += b"\x00\x00\x00\x00" # compressed size
				header_common += b"\x00\x00\x00\x00" # uncompressed size
				header_common += len(path).to_bytes(2, "little") # name length
				header_common += b"\x00\x00" # extra field length
				
				zipf.write(b"PK\x03\x04") # magic number (local data)
				zipf.write(header_common)
				zipf.write(path) # file name
				# no extra field data
				# no file data (because directory)
				
				central_directory += b"PK\x01\x02" # magic number (central directory entry)
				central_directory += (63).to_bytes(1, "little") # version made by (6.3)
				central_directory += b"\x00" # attribute format (DOS)
				central_directory += header_common
				central_directory += b"\x00\x00" # file comment length
				central_directory += b"\x00\x00" # disk number start
				central_directory += b"\x00\x00" # internal file attributes
				central_directory += (1 << 4).to_bytes(4, "little") # external file attributes (directory)
				central_directory += local_header_offset.to_bytes(4, "little") # offset to local header
				central_directory += path # file name
				# no extra field data
				# no file comment data
				
				num_central_directory_entries += 1
			
			for file in parsed.toc_files:
				local_header_offset = zipf.tell()
				path = join_dir_file_name(file.directory.path, file.name).replace(b"\\", b"/")
				modified = pack_zip_date_time(file.modified)
				
				header_common = b""
				header_common += (10 if file.is_uncompressed else 25).to_bytes(1, "little") # min. version to extract (2.5 if DCL Implode-compressed, 1.0 if stored)
				header_common += b"\x00" # attribute format (DOS)
				header_common += b"\x00\x00" # flags (none needed)
				header_common += (b"\x00\x00" if file.is_uncompressed else b"\x0a\x00") # compression method (stored or DCL Implode)
				header_common += modified # modified
				header_common += (zlib.crc32(file.data_compressed) if file.is_uncompressed else 0).to_bytes(4, "little") # CRC-32 (can't calculate this for DCL Implode-compressed data!)
				header_common += file.len_data_compressed.to_bytes(4, "little") # compressed size
				header_common += file.len_data_uncompressed.to_bytes(4, "little") # uncompressed size
				header_common += len(path).to_bytes(2, "little") # name length
				header_common += b"\x00\x00" # extra field length
				
				zipf.write(b"PK\x03\x04") # magic number (local data)
				zipf.write(header_common)
				zipf.write(path) # file name
				# no extra field data
				zipf.write(file.data_compressed)
				
				central_directory += b"PK\x01\x02" # magic number (central directory entry)
				central_directory += (63).to_bytes(1, "little") # version made by (6.3)
				central_directory += b"\x00" # attribute format (DOS)
				central_directory += header_common
				central_directory += b"\x00\x00" # file comment length
				central_directory += b"\x00\x00" # disk number start
				central_directory += b"\x00\x00" # internal file attributes
				central_directory += file.attributes.to_bytes(4, "little") # external file attributes (directory)
				central_directory += local_header_offset.to_bytes(4, "little") # offset to local header
				central_directory += path # file name
				# no extra field data
				# no file comment data
				
				num_central_directory_entries += 1
			
			central_directory_offset = zipf.tell()
			zipf.write(central_directory)
			zipf.write(b"PK\x05\x06") # magic number (end of central directory)
			zipf.write(b"\x00\x00") # current disk number
			zipf.write(b"\x00\x00") # start of central directory disk number
			zipf.write(num_central_directory_entries.to_bytes(2, "little")) # number of central directory entries on this disk
			zipf.write(num_central_directory_entries.to_bytes(2, "little")) # total number of central directory entries
			zipf.write(len(central_directory).to_bytes(4, "little")) # central directory size (excluding end of central directory)
			zipf.write(central_directory_offset.to_bytes(4, "little")) # central directory start offset
			zipf.write(b"\x00\x00") # ZIP file comment length
			# no ZIP file comment data
		
		archive_timestamp = timestamp_from_dos_datetime(parsed.header.modified)
		os.utime(output_file, (archive_timestamp, archive_timestamp))


if __name__ == "__main__":
	main()
