#!/usr/bin/env python3
"""Exercise persistent intent and ownership using real X.509 fixtures."""
import pathlib, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='magicnet-cert-test-') as tmp:
    root=pathlib.Path(tmp)
    classes=root/'classes'; classes.mkdir()
    subprocess.run(['javac','--release','8','-d',str(classes),str(ROOT/'crates/magicnet-cli/android/CertificatePolicy.java')],check=True)
    module=root/'module'; store=root/'store'; removed=root/'removed'
    store.mkdir(); removed.mkdir()
    config=module/'.config/magicnet/certificate-policy'; config.mkdir(parents=True)
    for name,subject in [('11111111.0','/CN=China Test/O=Fixture'),('22222222.0','/CN=Other Test/O=Fixture')]:
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(store/name),'-days','1','-subj',subject],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def run(action,ok=True):
        result=subprocess.run(['java','-cp',str(classes),'io.github.magicnet.CertificatePolicy',str(module),str(store),str(removed),action],capture_output=True,text=True)
        assert (result.returncode==0)==ok,result.stderr
        return result.stdout
    (config/'rules').write_text('keyword=CHINA\n')
    assert 'matched=1' in run('preview')
    run('disable'); run('apply')
    assert [p.name for p in removed.iterdir()]==['11111111.0']
    run('restore'); run('restore'); run('apply'); assert not list(removed.iterdir())
    # Existing user disable must never become module-owned.
    (removed/'11111111.0').write_bytes((store/'11111111.0').read_bytes())
    run('disable'); run('restore'); assert (removed/'11111111.0').exists()
    (removed/'11111111.0').unlink()
    fp=subprocess.check_output(['openssl','x509','-in',str(store/'22222222.0'),'-noout','-fingerprint','-sha256'],text=True).strip().split('=',1)[1]
    (config/'rules').write_text('sha256='+fp+'\n')
    run('disable'); assert (removed/'22222222.0').exists()
    # Changed evidence blocks destructive restore and retains ownership.
    (removed/'22222222.0').write_text('changed')
    run('restore',False)
    assert (module/'.state/certificate-policy/owned/22222222.0').exists()
    (removed/'22222222.0').write_bytes((store/'22222222.0').read_bytes())
    (config/'rules').unlink(); run('restore'); assert not list(removed.iterdir())
    (config/'rules').write_text('subject=O=Fixture,CN=Other Test\n')
    assert 'matched=1' in run('preview')
    # Invoke the production uninstall helper with an isolated module and real backend.
    (config/'rules').write_text('keyword=china\n')
    run('disable')
    wrapper=module/'certificate-policy'
    wrapper.write_text('#!/bin/sh\nexec java -cp "'+str(classes)+'" io.github.magicnet.CertificatePolicy "'+str(module)+'" "'+str(store)+'" "'+str(removed)+'" "$1"\n')
    wrapper.chmod(0o755)
    cli=module/'cli'; cli.write_text('#!/bin/sh\nexit 0\n'); cli.chmod(0o755)
    subprocess.run(['sh','-c','. "$1"; MODDIR=$2; export MODDIR; magicnet_uninstall_cleanup','sh',str(ROOT/'src/MagicNet/lib/magicnet/uninstall.sh'),str(module)],check=True)
    assert not list(removed.iterdir())
    print('PASS: keyword, exact subject/fingerprint, idempotence, durable restore, ownership, conflict recovery')
