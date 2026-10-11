"""Bounded publication-candidate integrity gate. No source-archive access or network."""
from pathlib import Path
import hashlib,json,re,struct
root=Path(__file__).resolve().parent
manifest=json.loads((root/'SOURCES.json').read_text())
expected=manifest['files']
actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '.git' not in p.relative_to(root).parts}
assert actual == set(expected)|{'SOURCES.json'}, 'unexpected or missing publication file'
for name,digest in expected.items():
 b=(root/name).read_bytes()
 assert hashlib.sha256(b).hexdigest()==digest, 'publication integrity mismatch'
 if name.endswith('.png'):
  assert b[:8]==b'\x89PNG\r\n\x1a\n'
  pos=8
  while pos<len(b):
   length=struct.unpack('>I',b[pos:pos+4])[0]
   assert b[pos+4:pos+8] in (b'IHDR',b'IDAT',b'IEND'), 'unexpected PNG metadata'
   pos+=length+12
 elif name.endswith(('.md','.json')):
  text=b.decode()
  patterns=[r'/(?:home|tmp|Users)/',r'(?i)Bearer\s+[A-Za-z0-9._-]{12,}',r'(?i)(?:api[_-]?key|access[_-]?token|session[_-]?id)\s*[:=]\s*["\']?[A-Za-z0-9._-]{12,}',r'-----BEGIN .*PRIVATE KEY-----',r'\bsk-[A-Za-z0-9]{20,}',r'(?<![\w@])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}']
  assert not any(re.search(p,text) for p in patterns), 'potential private data pattern; manual review required'
# Author's standing publication boundary: no writing-process conversation links.
for name in list(expected)+['SOURCES.json']:
 if name.endswith(('.md','.json')):
  content=(root/name).read_text()
  assert not re.search(r'https?://(?:chatgpt\.com|chat\.openai\.com|claude\.ai|gemini\.google\.com)(?:/|\b)',content,re.I), 'writing-process link forbidden'
  assert 'innomen.substack.com/p/a-chat-with-dave-i-hope' not in content, 'writing-process redirect forbidden'
assert not any(re.search(p,(root/'SOURCES.json').read_text()) for p in patterns), 'potential private data in source manifest'
# Contact metadata is part of a GitHub release even though it is not a source file.
if (root/'.git').exists():
 import subprocess
 emails=subprocess.check_output(['git','-C',str(root),'log','--format=%ae%n%ce'],text=True).splitlines()
 assert all(email.endswith('@users.noreply.github.com') for email in emails), 'Git contact metadata must use GitHub privacy addresses'
for item in manifest['sources']:
 assert item['sha256']==expected[item['path']], 'source manifest mismatch'
print('PASS: allowlist, file hashes, source manifest, PNG metadata and bounded text sweep')
