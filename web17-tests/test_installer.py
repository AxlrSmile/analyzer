#!/usr/bin/env python3
"""Offline Web 1.7 installer tests: correct baseline, conflicts, idempotence, rollback expectations."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parents[1]
V16=HERE/'web17-tests/fixtures/web16'
FILES=['src/main/resources/static/index.html','src/main/resources/static/web.js',
 'src/main/resources/static/web.css','src/main/resources/static/web-insights.js']
REQUIRED=['src/main/resources/static/web-diagnostics.js',
          'src/main/java/com/analyzerweb/WebFindingDiagnostics.java']

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

class InstallerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.root=Path(self.tmp.name)
  shutil.copy2(HERE/'apply_web_v17.py',self.root/'apply_web_v17.py')
  (self.root/'pom.xml').write_text('<project/>')
  for filename in FILES+REQUIRED:
   dst=self.root/filename
   dst.parent.mkdir(parents=True,exist_ok=True)
   shutil.copy2(V16/filename,dst)
  shutil.copytree(HERE/'web-v17-files',self.root/'web-v17-files')
 def tearDown(self): self.tmp.cleanup()
 def run_patch(self): return subprocess.run(['python',str(self.root/'apply_web_v17.py')],cwd=self.root,capture_output=True,text=True)
 def test_success_and_idempotence(self):
  before={filename:digest(self.root/filename) for filename in FILES}
  r=self.run_patch(); self.assertEqual(r.returncode,0,r.stderr)
  self.assertIn('Web 1.7 установлен',r.stdout)
  for filename in FILES:
   self.assertNotEqual(digest(self.root/filename),before[filename])
  backups=list((self.root/'web-v17-backup').glob('*'))
  self.assertEqual(len(backups),1)
  for filename in FILES:
   self.assertEqual(digest(backups[0]/filename),before[filename])
  second=self.run_patch(); self.assertEqual(second.returncode,0,second.stderr)
  self.assertIn('уже установлен',second.stdout)
  self.assertEqual(len(list((self.root/'web-v17-backup').glob('*'))),1)
 def test_refuses_edited_baseline_before_writing(self):
  changed=self.root/FILES[0]
  changed.write_text(changed.read_text()+'\n<!-- changed locally -->\n')
  untouched={f:digest(self.root/f) for f in FILES}
  r=self.run_patch()
  self.assertNotEqual(r.returncode,0)
  self.assertIn('КОНФЛИКТ',r.stderr)
  self.assertFalse((self.root/'web-v17-backup').exists())
  self.assertFalse((self.root/'src/main/resources/static/web-dashboard.js').exists())
  self.assertEqual(untouched,{f:digest(self.root/f) for f in FILES})
 def test_refuses_wrong_web16_version(self):
  (self.root/REQUIRED[0]).write_text('wrong')
  r=self.run_patch()
  self.assertNotEqual(r.returncode,0)
  self.assertIn('Web 1.6',r.stderr)
  self.assertFalse((self.root/'web-v17-backup').exists())
 def test_refuses_modified_payload(self):
  (self.root/'web-v17-files'/FILES[0]).write_text('modified!')
  r=self.run_patch()
  self.assertNotEqual(r.returncode,0)
  self.assertIn('Повреждён',r.stderr)
 def test_refuses_missing_project(self):
  (self.root/'pom.xml').unlink()
  r=self.run_patch()
  self.assertNotEqual(r.returncode,0)
  self.assertIn('pom.xml',r.stderr)

if __name__=='__main__': unittest.main()
