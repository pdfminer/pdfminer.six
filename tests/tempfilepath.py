"""Helper module, which provides a TemporaryFilePath() context manager"""

import tempfile
import os


class TemporaryFilePath():
    """
    A context manager class, which generates temporary file name
    (but, conroraly to standard tempfile.NamedTemporaryFile() does not create
    and open such file).
    Upon exit from the context manager block, he will attempt to delete the
    file with the generated file name.

    Minimal usage example:

        with TemporaryFilePath() as temp_file_name:
            with open(temp_file_name, "w") as temp_file:
                temp_file.write("some test data, which goes to the file")
                # some test code is here which reads data out of temp_file

    Arguments:
        'suffix' -- If 'suffix' is not None, the file name will end with
        that suffix, otherwise there will be no suffix.

        'prefix' -- If 'prefix' is not None, the file name will begin with
        that prefix, otherwise a default prefix is used.

        'dir' -- If 'dir' is not None, the file will be created in that
        directory, otherwise a default directory is used.

        'delete' -- whether the file is deleted at the end (default True)
    """

    def __init__(self, suffix=None, prefix=None, dir=None, delete=True):
        self.suffix = suffix
        self.prefix = prefix
        self.dir = dir
        self.delete = delete

    def __enter__(self) -> str:
        # Temporary file will be created and closed immediately.
        # Functionality of NamedTemporaryFile() will insure, that temporary
        # file will be deleted upon closure.
        # We only need a name of the temporary file to be used further
        with tempfile.NamedTemporaryFile(suffix=self.suffix,
                                         prefix=self.prefix,
                                         dir=self.dir) as file:
            self.temp_file_name = file.name

        return self.temp_file_name

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.delete:
            try:
                os.remove(self.temp_file_name)

            # Exception 'FileNotFoundError' is acceptable as user may have not
            # created the file to start with or has deleted it himself
            except FileNotFoundError:
                pass
