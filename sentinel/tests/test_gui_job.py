"""Regression test for the GUI thread-pool Job helper.

A QRunnable autodeletes right after run() returns. If its cross-thread "done"
signal has not yet been delivered to the GUI event loop, deleting the sender
drops the queued slot and the callback never fires — a button would stay stuck
on "…in corso" forever. Job keeps each in-flight job alive until its callback
has actually run, so delivery is guaranteed. These tests submit many jobs under
a real QThreadPool + event loop and assert every callback fires and no job is
leaked.
"""

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QCoreApplication, QEventLoop, QThreadPool, QTimer
    from cyberdistro_sentinel.gui.app import Job, _LIVE_JOBS
    HAVE_QT = True
except Exception:                                 # noqa: BLE001 — environment without PySide6
    HAVE_QT = False


@unittest.skipUnless(HAVE_QT, "PySide6 non disponibile")
class TestJobDelivery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def _pump(self, predicate, timeout_ms=10000):
        loop = QEventLoop()
        timer = QTimer()
        timer.timeout.connect(lambda: loop.quit() if predicate() else None)
        timer.start(5)
        guard = QTimer()
        guard.setSingleShot(True)
        guard.timeout.connect(loop.quit)
        guard.start(timeout_ms)
        loop.exec()
        timer.stop()
        guard.stop()

    def test_every_callback_fires_and_no_job_leaks(self):
        _LIVE_JOBS.clear()
        pool = QThreadPool()
        pool.setMaxThreadCount(2)                  # like the 2-core live system
        got = []
        n = 50
        for i in range(n):
            pool.start(Job(lambda i=i: i * 2, got.append))
        self._pump(lambda: len(got) == n)
        self.assertEqual(sorted(got), [i * 2 for i in range(n)])
        self.assertEqual(len(_LIVE_JOBS), 0)      # all released after delivery

    def test_exception_in_work_is_delivered_not_lost(self):
        _LIVE_JOBS.clear()
        pool = QThreadPool()
        pool.setMaxThreadCount(2)
        got = []

        def boom():
            raise RuntimeError("kaboom")

        pool.start(Job(boom, got.append))
        self._pump(lambda: len(got) == 1)
        self.assertEqual(len(got), 1)
        self.assertIsInstance(got[0], Exception)
        self.assertEqual(len(_LIVE_JOBS), 0)


if __name__ == "__main__":
    unittest.main()
