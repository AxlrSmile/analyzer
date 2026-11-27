#!/usr/bin/env python3
from html.parser import HTMLParser
from pathlib import Path
class Parser(HTMLParser):
 def __init__(self):
  super().__init__();self.ids=[];self.scripts=[]
 def handle_starttag(self,tag,attributes):
  attrs=dict(attributes)
  if 'id' in attrs:self.ids.append(attrs['id'])
  if tag=='script':self.scripts.append(attrs.get('src'))

path=Path(__file__).resolve().parents[1]/'web-v17-files/src/main/resources/static/index.html'
p=Parser();p.feed(path.read_text(encoding='utf-8'))
assert len(p.ids)==len(set(p.ids)), 'duplicate HTML ids'
assert p.scripts.index('/web-dashboard.js')<p.scripts.index('/web.js')
expected=['dashboardQuery','dashboardSeverity','dashboardOrigin','dashboardCwe','dashboardReview',
 'dashboardFp','dashboardEvidence','modelComparisonBody','findingsBody']
assert all(key in p.ids for key in expected), 'missing dashboard element'
assert 'Web 1.7' in path.read_text(encoding='utf-8')
print('Web 1.7 HTML structure: PASS')
