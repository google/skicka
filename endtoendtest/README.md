# endtoendtest

This is a small utility for end to end testing of skicka.  It creates a
small hierarchy of files in a temporary directory on the local disk,
uploads it to Google Drive using skicka, downloads those files to a
different local directory, and then makes sure that the contents of the two
directories match (including file contents, permissions, and moficiation
times.)

It then goes through a series of iterations of making a set of changes to
the local files, including changing file contents, changing permissions and
modification times, and adding new files and directories.  Each time, it
uploads the files to Drive, downloads again, and makes sure everything
matches up.

To use this program, make sure that you have skicka in your PATH and then
just run endtoendtest after installing it.
