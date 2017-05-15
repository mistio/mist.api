# TODO: Move these to mist.api.helpers

import os
import urllib
import tarfile
import zipfile
import logging


log = logging.getLogger(__name__)


def download(url, path=None):
    """Download a file over HTTP."""
    name, headers = urllib.urlretrieve(url, path)  # TODO: Verify status code?
    log.debug('Downloaded %s to %s', url, name)
    return name


def unpack(filename, dirname='.'):
    """Unpack a tarball or zip archive."""
    dirname = os.path.abspath(dirname)
    if not os.path.isdir(dirname):
        raise Exception('%s is not a directory' % dirname)
    if tarfile.is_tarfile(filename):
        log.debug('Unpacking %s tarball in %s directory', filename, dirname)
        tfile = tarfile.open(filename)
        tfile.extractall(dirname)
    elif zipfile.is_zipfile(filename):
        log.debug('Unpacking %s zip in %s directory', filename, dirname)
        zfile = zipfile.ZipFile(filename)
        zfile.extractall(dirname)
    else:
        raise TypeError('File %s is not a valid tar or zip archive' % filename)


def find_path(filename, dirname='.'):
    """Find the absolute path of a file."""
    dirname = os.path.abspath(dirname)
    if os.path.isdir(dirname):
        for dirpath, dirnames, filenames in os.walk(dirname):
            if filename in filenames:
                log.debug('Found file %s under %s', filenames, dirpath)
                return os.path.abspath(os.path.join(dirpath, filename))
        raise Exception('Failed to locate %s under %s', filename, dirname)
    raise Exception('%s is not a directory' % dirname)
