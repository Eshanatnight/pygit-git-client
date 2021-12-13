import enum
import sys
import os
import hashlib
import zlib
import collections
import argparse
import difflib
import operator
import  stat
import struct
import time
import urllib.request


# Data for one entry in the git index
IndexEntry = collections.namedtuple("IndexEntry", [
    "ctime_s", "ctime_n", "mtime_s", "dev",
    "ino", "mode", "uid", "gid",
    "size", "sha1", "flags", "path"
])

class ObjectType(enum.Enum):
    """
    Object type enum. There are other types too, but we don't need them.
    See "enum object_type" in git's source (git/cache.h).
    """
    commit = 1
    tree = 2
    blob = 3


def read_file(path):  # -> bytes ?
    """
    This should read the contents of a file
    at the given path in bytes
    """
    with open(path, 'rb') as file:
        return file.read()


def write_file(path, data) -> int:
    """
    Write the data bytes to the file at the given path
    :param path: string
    :param data:
    :return file.write(data): -> int ?
    """
    with open(path, 'wb') as file:
        return file.write(data)


def init(repo):
    """
    Create a directory for the repo and initialize
    .pygit directory, similar to how git works
    :param repo:
    :return No_Return:
    """
    # If the folder exists, then it might throw a traceback
    os.mkdir(repo)
    os.mkdir(os.path.join(repo, ".pygit"))
    for name in ["objects", "refs", "refs/heads"]:
        os.mkdir(os.path.join(repo, ".pygit", name))
    write_file(os.path.join(repo, ".pygit", "HEAD"), b"ref: refs/heads/master")
    print(f"Initialized Empty Repository: {repo}")


def hash_objects(data, object_type, write=True):
    """
    Compute hash of object data of given type and write to object store if
    "write" is True.
    :return SHA-1 object hash as hex string:
    """
    header = f"{object_type} {len(data)}".encode()

    """
    Each object has a small header including the type and size in bytes.This is followed by a NULL byte and then
    the file’s data bytes. This whole thing is zlib - compressed and written to .pygit / objects / ab / cd... 
    """
    full_data = header + b"\x00" + data
    sha1 = hashlib.sha1(full_data).hexdigest()

    if (write):
        path = os.path.join(".pygit", "objects", sha1[:2], sha1[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data))

    return sha1


def find_object(sha1_prefix):
    """
    Find object with given SHA-1 prefix and return path to object in object
    store, or raise ValueError if there are no objects or multiple objects
    with this prefix.
    """

    if (len(sha1_prefix) < 2):
        raise ValueError("Hash Prefix must be 2  or more characters")
    obj_dir = os.path.join(".pygit", "objects", sha1_prefix[:2])
    rest = sha1_prefix[2:]
    objects = [name for name in os.listdir(obj_dir) if name.startswith(rest)]

    if not objects:
        raise ValueError("Object {!r} not found".format(sha1_prefix))

    if len(objects) >= 2:
        raise ValueError("Multiple Objects ({}) with prefix {!r}".format(len(objects), sha1_prefix))

    return os.path.join(obj_dir, objects[0])


def read_object(sha1_prefix):
    """
    Read object with given SHA-1 prefix and
    return tuple of (object_type, data_bytes),
    or raise ValueError if not found.
    """

    path = find_object(sha1_prefix)
    full_data = zlib.decompress(read_file(path))
    null_index = full_data.index(b"\x00")
    header = full_data[:null_index]
    object_type, size_str = header.decode().split()
    size = int(size_str)
    data = full_data[null_index + 1:]

    assert size == len(data), f"Expected size {size}, got {len(data)} bytes"
    return (object_type, data)


def cat_file(mode, sha1_prefix):
    """
    Write the contents of (or info about) object with given SHA-1 prefix to
    stdout.
    If mode is 'commit', 'tree', or 'blob', print raw data bytes of
    object.
    If mode is 'size', print the size of the object.
    If mode is 'type', print the type of the object.
    If mode is 'pretty', print a prettified version of the object.
    """

    object_type, data = read_object(sha1_prefix)
    if mode in ["commit", "tree", "blob"]:
        if object_type != mode:
            raise ValueError(f"Expected {mode} got {object_type}")
        sys.stdout.buffer.write(data)

    elif (mode == "size"):
        print(len(data))
        
    elif (mode == "type"):
        print(object_type)

    elif (mode == "pretty"):
        if (object_type in ["commit", "blob"]):
            sys.stdout.buffer.write(data)

        elif (object_type == "tree"):
            # read_tree function need to be defined
            for mode, path, sha1 in read_tree(data=data)
                type_str = "tree" if stat.S_ISDIR(mode) else "blob"
                print(f"{mode:06o} {type_str} {sha1} {path}")

        else:
            assert False, "Unhandled Object Type {!r}".format(object_type)

    else:
        raise ValueError(f"Unexpected mode {mode!r}")#.format(mode))


def read_index():
    """
    Read git index file
    :return: IndexEntry List object
    """
    try:
        data = read_file(os.path.join(".pygit", "index"))
    except FileNotFoundError:
        return []   # Return an empty list if error caught

    digest = hashlib.sha1(data[:-20]).digest()
    assert digest == data[:-20], "Invalid Index Checksum"

    signature, version, num_entries = struct.unpack("!4sLL", data[:12])

    # assertions for signature and version
    assert signature == b"DIRC", f"Invalid Index Signature {signature}"
    assert version == 2, f"Unknown Index Version {version}"

    entry_data = data[12:-20]
    entries = [] # An empty arrays of entries
    i = 0
    while i + 62 < len(entry_data):
        fields_end = i + 62
        fields = struct.unpack("LLLLLLLLLL20sH", entry_data[i :fields_end])
        path_end = entry_data.index(b"\x00", fields_end)
        path = entry_data[fields_end:path_end]
        entry = IndexEntry(*(fields + (path.decode(),)))
        entries.append(entry)
        entry_length = ((62 +len(path) + 8) // 8) * 8
        i += entry_length

    assert len(entries) == num_entries
    return entries


def ls_files(details=False):
    """
    This should print all the Files in the index
    (including mode, SHA1 and stage number (if :param: details == True)
    :param details:
    :return: void
    """

    for entry in read_index():
        if details:
            stage = (entry.flags >> 12) & 3
            print(f"{entry.mode:6o}, {entry.sha1.hex()}, {stage:}\t{entry.path}")
        else:
            print(entry.path)


def get_status():
    """
    Get Status of the working copy,
    :return: a tuple of (changed_paths, new_paths, deleted_path)
    """
    paths = set()

    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d != ".pygit"]
        for file in files:
            path = os.path.join(root, file)
            path = path.replace('\\', "/")
            if path.startswith("./"):
                path = path[2:]     # strip the initial "./"
            paths.add(path)

    entries_by_path = {e.path: e for e in read_index()}
    entry_paths = set(entries_by_path)
    changed = {
        p for p in (paths & entry_paths)
        if hash_objects(read_file(p), "blob", write=False) != entries_by_path[p].sha1.hex()
    }

    new = paths - entry_paths
    deleted = entry_paths - paths
    return (sorted(changed), sorted(new), sorted(deleted))


def status():
    """
    Show the status of current working copy.
    """
    changed, new, deleted = get_status()


def diff():

