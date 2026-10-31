"""Application lifecycle: lock before touching an IPC path; verify permissions."""
import fcntl
import grp
import os
from pathlib import Path
import stat

from bmcyber.constants.DZMQ import DZMQ


class IPCEndpoint:
    def __init__(self, path, *, uid=0, gid=None):
        self.path = Path(path)
        self.uid = uid
        self.gid = grp.getgrnam(DZMQ.GROUP).gr_gid if gid is None else gid
        self.descriptor = None
        self.inode = None

    def __enter__(self):
        for path in (self.path.parent, *self.path.parent.parents):
            if path.is_symlink():
                raise ValueError(f'symlink in IPC directory path: {path}')
        info = self.path.parent.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or info.st_gid != self.gid
                or stat.S_IMODE(info.st_mode) != DZMQ.DIRECTORY_MODE):
            raise ValueError('IPC directory must have the service owner/group and mode 0750')
        descriptor = os.open(self.path.parent / 'service.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.path.exists() or self.path.is_symlink():
                info = self.path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.uid or info.st_gid != self.gid:
                    raise ValueError('refusing to remove an unrelated IPC path')
                self.path.unlink()
        except BaseException:
            os.close(descriptor)
            raise
        self.descriptor = descriptor
        return self

    def bound(self):
        info = self.path.lstat()
        self.inode = info.st_ino
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.uid or info.st_gid != self.gid
                or stat.S_IMODE(info.st_mode) != DZMQ.SOCKET_MODE):
            raise ValueError('IPC socket must have the service owner/group and mode 0660 from creation')

    def __exit__(self, *_):
        try:
            if self.inode is not None and self.path.exists() and self.path.lstat().st_ino == self.inode:
                self.path.unlink()
        finally:
            os.close(self.descriptor)
