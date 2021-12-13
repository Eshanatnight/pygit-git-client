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


def read_file(path) -> bytes:
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


def init(repo) -> None:
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
    write_file(os.path.join(repo, ".pygit", "HEAD"), b"ref: refs/heads/main")
    print(f"Initialized Empty Repository: {repo}")


def hash_objects(data, object_type, write=True) -> str:
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

    if write:
        path = os.path.join(".pygit", "objects", sha1[:2], sha1[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data))

    return sha1


def find_object(sha1_prefix) -> str:
    """
    Find object with given SHA-1 prefix and return path to object in object
    store, or raise ValueError if there are no objects or multiple objects
    with this prefix.
    """

    if len(sha1_prefix) < 2:
        raise ValueError("Hash Prefix must be 2  or more characters")
    obj_dir = os.path.join(".pygit", "objects", sha1_prefix[:2])
    rest = sha1_prefix[2:]
    objects = [name for name in os.listdir(obj_dir) if name.startswith(rest)]

    if not objects:
        raise ValueError("Object {!r} not found".format(sha1_prefix))

    if len(objects) >= 2:
        raise ValueError("Multiple Objects ({}) with prefix {!r}".format(len(objects), sha1_prefix))

    return os.path.join(obj_dir, objects[0])


def read_object(sha1_prefix) -> tuple:
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
    return object_type, data


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

    elif mode == "size":
        print(len(data))
        
    elif mode == "type":
        print(object_type)

    elif mode == "pretty":
        if object_type in ["commit", "blob"]:
            sys.stdout.buffer.write(data)

        elif object_type == "tree":
            # read_tree function need to be defined
            for mode, path, sha1 in read_tree(data=data):
                type_str = "tree" if stat.S_ISDIR(mode) else "blob"
                print(f"{mode:06o} {type_str} {sha1} {path}")

        else:
            assert False, "Unhandled Object Type {!r}".format(object_type)

    else:
        raise ValueError(f"Unexpected mode {mode!r}")#.format(mode))


def read_index() -> list:
    """
    Read git index file
    :return: IndexEntry list object
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


def ls_files(details=False) -> None:
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


def get_status() -> tuple:
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
    return sorted(changed), sorted(new), sorted(deleted)


def status() -> None:
    """
    Show the status of current working copy.
    Just uses "get_status()" to compare the files in the index
    ot the files in the current working directory tree.
    And should print out the changes, deletions
    :return: void
    """
    changed, new, deleted = get_status()
    if changed:
        print("Changed Files: ")
        for path in changed:
            print("     ", path)

    if new:
        print("New File: ")
        for path in new:
            print("     ",path)

    if deleted:
        print("Deleted Files: ")
        for path in deleted:
            print("     ",path)


def diff() -> None:
    """
    Print the diff of the files changed
    Between index and working copy.
    uses the python difflib module.
    :return: void
    """
    changed, _, _ = get_status()  # Ignoring the new and deleted values

    # accumulates the paths into a list
    entries_by_path = { e.path: e for e in read_index() }
    for i, path in enumerate(changed):
        sha1 = entries_by_path[path].sha1.hex()
        object_type, data = read_object(sha1)

        assert object_type == "blob"

        index_lines = data.decode().splitlines()
        working_lines = read_file(path).decode().splitlines()
        diff_lines = difflib.unified_diff(
            index_lines, working_lines,
            f"{path} (index)",
            f"{path} (working)",
            lineterm=''
        )       # This returns an Iterator[str]
        for line in diff_lines:
            print(line)
        if i < len(changed) - 1:
            print('-' * 70)


def write_index(entries) -> None:
    """
    Write list of IndexEntry objects to the index files
    :return: void
    """

    packed_entries = []
    for entry in entries:
        entry_head = struct.pack(
            '!LLLLLLLLLL20sH', entry.ctime_s, entry.ctime_n,
            entry.mtime_s, entry.mtime_n, entry.dev, entry.ino,
            entry.mode, entry.uid, entry.gid, entry.size, entry.sha1,
            entry.flags
        )
        path = entry.path.decode()
        length = ((62 + len(path) + 8) // 8) * 8

        # Not sure if the calculations are correct though
        packed_entry = entry_head + path + b"\x00" * (length - len(path) - 62)
        packed_entries.append(packed_entry)
        
        header = struct.pack("!4sLL", b"DIRC", 2, len(entries))
        all_data =  header + b''.join(packed_entries)
        digest = hashlib.sha1(all_data).digest()
        write_file(os.path.join(".pygit", "index"), all_data + digest)


def add(paths):
    """
    Add the files to the index files
    :param paths:
    :return void:
    """
    path = [p.replace('\\', '/') for p in paths]
    all_entries = read_index()
    entries = [e for e in all_entries if e.path not in paths]

    for path in paths:
        sha1 = hash_objects(read_file(path), "blob")
        st = os.stat(path)
        flags = len(path.encode())
        assert flags < (1 << 12) # Less than 0b1000000000000 amount?

        entry = IndexEntry(
                int(st.st_ctime), 0, int(st.st_mtime), 0, st.st_dev,
                st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
                bytes.fromhex(sha1), flags, path
        )
        entries.append(entry)

    entries.sort(key=operator.attrgetter("path"))
    write_index(entries)


def write_tree() -> str:
    """
    This will write the tree from the current index entry
    :return hash_objects(...) -> str:
    """
    tree_entries = []
    for entry in read_index():
        assert '/' not in entry.path, "Currently only supports a single top level directory"
        #mode_path = "{:o} {}".format(entry.mode, entry.path).encode()
        mode_path = f"{entry.mode.encode():o} {entry.path.encode()}"
        tree_entry = mode_path + b"\x00" + entry.sha1
        # Showing warning around the byte Null unexpected type. May cause problems ?

        tree_entries.append(tree_entry)

    return hash_objects(b''.join(tree_entries), "tree")


def get_local_main_hash():
    """
    Gets the current commit hash (SHA1 String) of local main branch
    :return read_file(...) -> bytes:
    """
    main_path = os.path.join(".pygit", "refs", "heads", "main")
    try:
        return read_file(main_path).decode().strip()
    except FileNotFoundError:
        return None


def commit(message, author=None):
    """
    commit the current state of the index to main with the given commit message
    :param message:
    :param author:
    :return hash of the commit object -> str:
    """
    tree = write_tree()
    parent = get_local_main_hash()
    if author is None:
        author = f"{os.environ['GIT_AUTHOR_NAME']} <{os.environ['GIT_AUTHOR_EMAIL']}>"

    timestamp = int(time.mktime(time.localtime()))   # Index the time stamp
    utc_offset = -time.timezone
    author_time = "{} {}{:02}{:02}".format(
        timestamp, '+' if utc_offset > 0 else '-',
        abs(utc_offset) // 3600, (abs(utc_offset) // 60) % 60
    )           # If I am not wrong, this should format the author_time string properly

    lines = [ "tree" + tree ]
    if parent:
        lines.append("parent " + parent)
    lines.append(f"author {author} {author_time}")
    lines.append(f"commiter {author} {author_time}")
    lines.append("")
    lines.append(message)
    lines.append("")
    data = '\n'.join(lines).encode()
    sha1 = hash_objects(data, "commit")
    main_path = os.path.join(".pygit", "refs", "heads", "main")
    write_file(main_path, (sha1 + '\n').encode())
    print(f"committed to main: {sha1:16}")
    return sha1


def extract_lines(data) -> list:
    """
    Extract the list of lines from the given server data
    :param data:
    :return list:
    """
    lines = []
    i: int = 0

    for _ in range(1000):
        line_length = int(data[i:i + 4], base=16)
        line = data[i + 4: i + line_length]
        lines.append(line)

        if line_length == 0:
            i += 4              # Shift the index by 4 points

        else:
            i += line_length

        if len(data) < i :
            break

    return lines


def build_lines_data(lines):
    """
    Builds the byte string from given lines to send to the server
    :param lines:
    :return bytes:
    """
    result = []
    for line in lines:
        result.append(f"{(len(line) + 5 ):04x}".encode())
        result.append(line)
        result.append(b"\n")
    result.append(b"0000")
    return b''.join(result)


def get_remote_main_hash(git_url, username, password):
    """
    Get the commit hash of remote main branch
    :param git_url:
    :param username:
    :param password:
    :return sha1 hex string or none if no remote commits:
    """
    url = git_url + "/info/refs?service=git-receive-pack"
    response = https_request(url, username, password)      # function https_request needs to be defined
    lines = extract_lines(response)

    # assertions
    assert lines[0] == b"# service=git-receive-pack\n"
    assert lines[1] == b''

    if lines[2][:40] == b'0' * 40:
        return None

    main_sha1, main_ref = lines[2].split(b"\x00")[0].split()
    assert main_ref == b'refs/heads/main'
    assert len(main_sha1) == 40
    return main_sha1.decode()


def read_tree(sha1=None, data=None) -> list:
    """
    Read tree object with given SHA-1 (hex string) or data
    :param sha1:
    :param data:
    :return list of (mode, path, sha1) tuples:
    """
    if sha1 is not None:
        object_type, data = read_object(sha1)
        assert object_type == "tree"
    elif data is None:
        raise TypeError("Must specify \"sha1\" or \"data\" ")

    i: int = 0
    entries = []
    for _ in range(1000):
        end = data.find(b"\x00", i)
        if end == -1:
            break

        mode_str, path = data[i:end].decode().split()
        mode = int(mode_str, 8)
        digest = data[end + 1: end + 21]
        entries.append((mode, path, digest.hex()))
        i = end + 1 + 20

    return entries


def find_tree_objects(tree_sha1):
    """
    Return set of SHA-1 hashes of all objects in this tree (recursively),
    including the hash of the tree itself.
    :param tree_sha1:
    :return set:
    """
    objects = {tree_sha1}
    for mode, path, sha1 in read_tree(sha1=tree_sha1)
        if stat.S_ISDIR(mode):
            objects.update(find_tree_objects(sha1))

        else:
            objects.add(sha1)

    return objects


def find_commit_objects(commit_sha1):
    """
    Return set of SHA-1 hashes of all objects in this commit (recursively),
    its tree, its parents, and the hash of the commit itself.
    :param commit_sha1:
    :return set:
    """
    objects = {commit_sha1}
    object_type, commit = read_object(commit_sha1)

    assert object_type == "commit"
    lines = commit.decode().splitlines()
    tree = next(l[5:45] for l in lines if l.startswith("tree "))
    objects.update(find_tree_objects(tree))
    parents = (l[7:47] for l in lines if l.startswith("parent "))

    for parent in parents:
        objects.update(find_commit_objects(parent))

    return objects

