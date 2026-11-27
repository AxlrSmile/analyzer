import importlib.util
from pathlib import Path

p = Path(__file__).resolve().parents[1] / 'web-v18-files' / 'benchmark-dataset' / 'evaluate_web_v18.py'
spec = importlib.util.spec_from_file_location('evaluate_web_v18', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def report(name, origin, findings, *, complete=1, partial=0, sast=True):
    return {'loadedFiles':1,'llmComplete':complete,'llmPartial':partial,'llmFailed':0,
            'sastCompleted':sast,'files':[{'name':name,'findings':[{'origin':origin} for _ in range(findings)]}]}


def test_file_metrics():
    truth={'Case008.java':True,'Case011.java':False}
    cases=[('a',report('Case008.java','LLM',1)),('b',report('Case011.java','LLM',0))]
    r=m.evaluate(truth,cases,'LLM')
    assert r['counts']=={'TP':1,'FP':0,'TN':1,'FN':0}
    assert r['precision']==1.0 and r['recall']==1.0 and r['f1']==1.0


def test_partial_not_counted_clean():
    truth={'Case008.java':True}
    r=m.evaluate(truth,[('p',report('Case008.java','LLM',0,complete=0,partial=1))],'LLM')
    assert r['acceptedRuns']==0 and r['counts']['FN']==0 and len(r['excluded'])==1


def test_false_positive():
    truth={'Case008.java':True,'Case011.java':False}
    r=m.evaluate(truth,[('a',report('Case008.java','LLM',1)),('b',report('Case011.java','LLM',1))],'LLM')
    assert r['counts']=={'TP':1,'FP':1,'TN':0,'FN':0}
    assert r['precision']==.5 and r['recall']==1.0


def test_no_sast_not_clean():
    r=m.evaluate({'Case011.java':False},[('a',report('Case011.java','LLM',0,sast=False))],'Semgrep')
    assert r['acceptedRuns']==0 and r['counts']['TN']==0


def test_multi_file_not_relabelled():
    r=m.evaluate({'Case008.java':True},[('a',{'loadedFiles':2,'files':[{'name':'Case008.java','findings':[]}],'llmComplete':1})],'LLM')
    assert r['acceptedRuns']==0


if __name__=='__main__':
    for fn in [test_file_metrics,test_partial_not_counted_clean,test_false_positive,test_no_sast_not_clean,test_multi_file_not_relabelled]:
        fn()
    print('Web 1.8 benchmark evaluation: 5 tests passed')
