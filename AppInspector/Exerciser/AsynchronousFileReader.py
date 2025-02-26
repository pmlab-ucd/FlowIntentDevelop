#! /usr/bin/env python

# from http://stackoverflow.com/questions/11524586/accessing-logcat-from-android-via-python
import queue
import subprocess
import threading


class AsynchronousFileReader(threading.Thread):
    """
    Helper class to implement asynchronous reading of a file
    in a separate thread. Pushes read lines on a queue to
    be consumed in another thread.
    """

    def __init__(self, fd, q):
        assert isinstance(q, queue.Queue)
        assert callable(fd.readline)
        threading.Thread.__init__(self)
        self._fd = fd
        self._queue = q

    def run(self):
        """The body of the tread: read lines and put them on the queue."""
        for line in iter(self._fd.readline, ''):
            self._queue.put(line)

    def eof(self):
        """Check whether there is no more content to expect."""
        return not self.is_alive() and self._queue.empty()

    @staticmethod
    def ps():
        # You'll need to add any command line arguments here.
        process = subprocess.Popen(['adb', 'shell', 'ps'], stdout=subprocess.PIPE)

        # Launch the asynchronous readers of the process' stdout.
        stdout_queue = queue.Queue()
        stdout_reader = AsynchronousFileReader(process.stdout, stdout_queue)
        stdout_reader.start()

        # Check the queues if we received some output (until there is nothing more to get).
        still_looking = True
        try:
            while still_looking and not stdout_reader.eof():
                while not stdout_queue.empty():
                    line = stdout_queue.get()
                    print(line)

        finally:
            process.kill()
