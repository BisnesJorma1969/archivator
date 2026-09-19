from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from poc.archivator_lib.common import WORK_DIR
from poc.archivator_lib.external import ZstdWriter, executable, run
from poc.archivator_lib.limits import input_limit, parity_plan, stored_bound


class LimitTests(unittest.TestCase):
    def test_compressed_incompressible_frames_fit_budget(self):
        import random
        WORK_DIR.mkdir(exist_ok=True)
        with TemporaryDirectory(dir=WORK_DIR) as temporary:
            for limit in (8191, 65535, 262143):
                path = Path(temporary) / str(limit)
                size = input_limit(limit)
                writer = ZstdWriter(path)
                writer.write(random.Random(limit).randbytes(size))
                writer.finish()
                self.assertLessEqual(path.stat().st_size, stored_bound(size))
                self.assertLessEqual(stored_bound(size), limit)

    def test_real_par2_packet_overhead_fits_budget(self):
        WORK_DIR.mkdir(exist_ok=True)
        with TemporaryDirectory(dir=WORK_DIR) as temporary:
            directory = Path(temporary).resolve()
            members = {}
            for number, length in enumerate((7, 9000, 22000)):
                name = f'input-{number}'
                (directory / name).write_bytes(bytes(length))
                members[name] = length
            for limit in (8000, 16000, 64000):
                plan = parity_plan(members, 1024, limit)
                prefix = f'set-{limit}'
                run([executable('par2'), 'create', '-q', '-t1', '-T1', '-s1024',
                     f'-c{plan.blocks}', '-u', f'-n{plan.volumes}',
                     str(directory / (prefix + '.par2')), *members], cwd=directory)
                sizes = [path.stat().st_size for path in directory.glob(prefix + '*.par2')]
                self.assertEqual(len(sizes), plan.volumes + 1)
                self.assertLessEqual(max(sizes), plan.largest_file)
                self.assertLessEqual(max(sizes), limit)
                self.assertLessEqual(sum(sizes), plan.total_bytes)
