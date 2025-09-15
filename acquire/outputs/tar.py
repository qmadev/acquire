from __future__ import annotations

import io
import tarfile
import sys
from typing import TYPE_CHECKING, BinaryIO

from acquire.crypt import EncryptedStream
from acquire.outputs.base import Output

if sys.version_info < (3, 14):
    try:
        from zstandard import ZstdCompressor
        HAS_ZSTDLIB = True
    except ImportError:
        HAS_ZSTDLIB = False

    
if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import FilesystemEntry

TAR_COMPRESSION_METHODS = {"gzip": "gz", "bzip2": "bz2", "xz": "xz", "zstd": "zst"}


class TarOutput(Output):
    """Tar archive acquire output format. Output can be compressed and/or encrypted.

    Args:
        path: The path to write the tar archive to.
        compress: Whether to compress the tar archive.
        compression_method: Compression method to use (Default: gzip). Supports "gzip", "bzip2", "xz", "zstd".
        encrypt: Whether to encrypt the tar archive.
        public_key: The RSA public key to encrypt the header with.
    """

    def __init__(
        self,
        path: Path,
        compress: bool = False,
        compression_method: str = "gzip",
        encrypt: bool = False,
        public_key: bytes | None = None,
    ) -> None:
        self.compression = None
        ext = ".tar" if ".tar" not in path.suffixes else ""
        mode = "w|" if encrypt else "w:"

        if compress:
            self.compression = TAR_COMPRESSION_METHODS.get(compression_method, "gz")

            if compression_method == "zstd" and EXTERNAL_ZSTD:
                self.zstd_compressor = ZstdCompressor()
                mode = "w|"
            else:
                mode += self.compression

            ext += f".{self.compression}" if f".{self.compression}" not in path.suffixes else ""

        if encrypt:
            ext += ".enc"

        self._fh = None
        self.path = path.with_suffix(path.suffix + ext)

        # We need to fix our encryption/zstd streams ourselves < Python 3.14
        if encrypt and compression_method == "zstd" and EXTERNAL_ZSTD:
            encrypted_stream = EncryptedStream(self.path.open("wb"), public_key)
            self._fh = self.zstd_compressor.stream_writer(writer=encrypted_stream)
            self.tar = tarfile.open(fileobj=self._fh, mode=mode)  # noqa: SIM115
        elif compression_method == "zstd" and EXTERNAL_ZSTD:
            self._fh = self.zstd_compressor.stream_writer(self.path.open("wb"))
            self.tar = tarfile.open(fileobj=self._fh, mode=mode)  # noqa: SIM115
        # > Python 3.14, zstd support is included in tarfile
        elif encrypt:
            self._fh = EncryptedStream(self.path.open("wb"), public_key)
            self.tar = tarfile.open(fileobj=self._fh, mode=mode) # noqa: SIM115
        else:
            self.tar = tarfile.open(name=self.path, mode=mode)  # noqa: SIM115

    def write(
        self,
        output_path: str,
        fh: BinaryIO,
        entry: FilesystemEntry | Path | None = None,
        size: int | None = None,
    ) -> None:
        """Write a file-like object to a tar file.

        The data from ``fh`` is written, while ``entry`` is used to get some properties of the file.

        Args:
            output_path: The path of the entry in the output.
            fh: The file-like object of the entry to write.
            entry: The optional filesystem entry to write.
            size: The optional file size in bytes of the entry to write.
        """
        stat = None
        size = size or getattr(fh, "size", None)

        if size is None and fh.seekable():
            offset = fh.tell()
            fh.seek(0, io.SEEK_END)
            size = fh.tell()
            fh.seek(offset)

        info = self.tar.tarinfo()
        info.name = output_path
        info.uname = "root"
        info.gname = "root"
        info.size = size or 0

        if entry:
            if entry.is_symlink():
                info.type = tarfile.SYMTYPE
                info.linkname = entry.readlink()
            elif entry.is_dir():
                info.type = tarfile.DIRTYPE

            stat = entry.lstat()

            if stat:
                info.mtime = stat.st_mtime

        self.tar.addfile(info, fh)

    def close(self) -> None:
        """Closes the tar file."""
        self.tar.close()
        if self._fh:
            self._fh.close()
