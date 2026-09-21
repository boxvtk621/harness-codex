#!/usr/bin/env python3
"""Disposable packaging/startup smoke. No native model calls or real secrets."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    completed = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if completed.returncode:
        detail = completed.stderr.strip()[-2000:] or completed.stdout.strip()[-2000:]
        raise RuntimeError(f'{Path(args[0]).name} failed: {detail}')
    return completed.stdout.strip()


def codex_denied_features():
    source = (ROOT / 'adapters/codex/adapter.go').read_text()
    match = re.search(r'var deniedNativeFeatures = \[\]string\{(.*?)\n\}', source, re.S)
    assert match is not None, 'Codex native feature deny list is missing'
    features = re.findall(r'"([a-z0-9_]+)"', match.group(1))
    assert features and len(features) == len(set(features)), 'Codex native feature deny list is invalid'
    return features



def codex_smoke(image, openssl_path=None):
    prefix = 'hl300-smoke-' + uuid.uuid4().hex
    volumes = {name: prefix + '-' + name for name in ('config', 'state', 'auth', 'workspace', 'native')}
    container = prefix + '-node'
    openssl = openssl_path or shutil.which('openssl')
    if Path('/opt/homebrew/opt/openssl@3/bin/openssl').exists():
        openssl = '/opt/homebrew/opt/openssl@3/bin/openssl'
    if not openssl:
        raise RuntimeError('OpenSSL 3 executable is required; pass --openssl')
    with tempfile.TemporaryDirectory(prefix='hl300-container-') as directory:
        root = Path(directory) / 'fixture'
        run(sys.executable, str(ROOT / 'scripts/setup.py'), '--directory', str(root),
            '--owner-id', 'fixture-owner',
            '--codex-executable', '/opt/codex/node_modules/.bin/codex', '--codex-home', '/auth/codex',
            '--codex-model', 'fixture-model', '--openssl', openssl, '--container')
        container_config_path = root / 'node-config' / 'node.json'
        container_config = json.loads(container_config_path.read_text())
        container_config['approvalMode'] = 'explicit_once'
        container_config_path.write_text(json.dumps(container_config, separators=(',', ':')) + '\n')
        (root / 'node-config' / 'tools.json').write_bytes(
            b'[{"name":"codex.command"},{"name":"codex.file_change"}]\n')
        created_volumes = []
        try:
            for volume in volumes.values():
                run('docker', 'volume', 'create', volume)
                created_volumes.append(volume)
            mounts = [
                '-v', volumes['config'] + ':/config', '-v', volumes['state'] + ':/state',
                '-v', volumes['auth'] + ':/auth', '-v', volumes['workspace'] + ':/workspace',
            ]
            metadata = run('docker', 'run', '--rm', '--network', 'none', '--read-only',
                           '--entrypoint', '/bin/sh', image, '-c',
                           "test -f /harness-tool-runner && test ! -L /harness-tool-runner "
                           "&& stat -c '%u:%g:%a' /harness-tool-runner")
            assert metadata == '0:0:555', 'Harness tool runner ownership or mode is unsafe'
            run('docker', 'run', '--rm', '--network', 'none', '--user', '0:0',
                '-v', str(root / 'node-config') + ':/source:ro',
                '-v', str(root) + ':/fixture:ro',
                '-v', volumes['config'] + ':/config', '-v', volumes['state'] + ':/state',
                '-v', volumes['auth'] + ':/auth', '-v', volumes['workspace'] + ':/workspace',
                '-v', volumes['native'] + ':/native',
                '--entrypoint', '/bin/sh', image, '-c',
                'cp -R /source/. /config/ '
                '&& mkdir -p /state/codex/home /auth/codex /native/home /native/codex '
                '&& chown -R 10001:10001 /config /state /auth /workspace /native '
                '&& mkdir /workspace/self-test && chown 10001:10001 /workspace/self-test '
                '&& chmod 700 /config /state /state/codex /state/codex/home /auth /auth/codex /workspace /workspace/self-test /native /native/home /native/codex')
            envelope = json.dumps({
                'protocolVersion': 1, 'mode': 'self-test', 'maximumOutput': 65536,
                'systemReadRoots': ['/usr', '/etc/ld.so.cache',
                                    '/etc/ssl/certs', '/dev/null', '/dev/urandom'],
                'request': {'callId': 'container-self-test', 'workspace': '/workspace/self-test',
                            'kind': 'command', 'command': {'command': ':', 'cwd': '.',
                                                          'access': 'write', 'timeoutMillis': 1000}},
            })
            isolated = subprocess.run([
                'docker', 'run', '-i', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '-v', volumes['config'] + ':/config:ro', '-v', volumes['state'] + ':/state',
                '-v', volumes['auth'] + ':/auth:ro', '-v', volumes['workspace'] + ':/workspace',
                '--entrypoint', '/harness-tool-runner', image, '--serve',
            ], input=envelope, capture_output=True, text=True, timeout=10)
            assert isolated.returncode == 0, 'Harness tool runner self-test process failed'
            self_test = json.loads(isolated.stdout)
            assert (self_test.get('protocolVersion') == 1 and self_test.get('success') is True
                    and not self_test.get('failure')), \
                'Harness tool runner isolation self-test failed: ' + repr(self_test)
            native_probe = r"""const {spawn}=require('node:child_process');
const denied=__DENIED__,features=Object.fromEntries(denied.map(name=>[name,false]));
const child=spawn('/opt/codex/node_modules/.bin/codex',['app-server','--listen','stdio://'],{env:{
HOME:'/native/home',CODEX_HOME:'/native/codex',PATH:'/opt/codex/node_modules/.bin:/usr/local/bin:/usr/bin:/bin',
SSL_CERT_FILE:'/etc/ssl/certs/ca-certificates.crt'},stdio:['pipe','pipe','ignore']});
let next=0,buffer='';const pending=new Map(),stop=()=>{try{child.kill('SIGTERM')}catch{}};
child.stdout.on('data',chunk=>{buffer+=chunk.toString('utf8');for(;;){const end=buffer.indexOf('\n');if(end<0)break;
const line=buffer.slice(0,end);buffer=buffer.slice(end+1);if(!line)continue;let frame;try{frame=JSON.parse(line)}catch(error){stop();continue}
if(frame.id===undefined||frame.method)continue;const saved=pending.get(String(frame.id));if(!saved)continue;pending.delete(String(frame.id));
frame.error?saved.reject(new Error('rpc '+String(frame.error.code))):saved.resolve(frame.result);}});
const call=(method,params)=>new Promise((resolve,reject)=>{const id=++next,timer=setTimeout(()=>{pending.delete(String(id));reject(new Error('timeout'))},10000);
pending.set(String(id),{resolve:value=>{clearTimeout(timer);resolve(value)},reject:error=>{clearTimeout(timer);reject(error)}});
child.stdin.write(JSON.stringify({id,method,params})+'\n');});
const notify=(method,params)=>child.stdin.write(JSON.stringify({method,params})+'\n');
(async()=>{await call('initialize',{clientInfo:{name:'harness-codex-smoke',title:'Harness Codex smoke',version:'0.153.4'}});notify('initialized',{});
const started=await call('thread/start',{model:'gpt-5.2-codex',cwd:'/workspace',approvalPolicy:'never',sandbox:'read-only',
developerInstructions:'deny-only container smoke',config:{features,mcp_servers:{},web_search:'disabled'}});
if(!started?.thread?.id||started.approvalPolicy!=='never'||started.sandbox?.type!=='readOnly'||started.sandbox?.networkAccess!==false)throw new Error('thread policy mismatch');
let cursor=null,pages=0;const observed=new Map();do{const params={threadId:started.thread.id,limit:100};if(cursor)params.cursor=cursor;
const page=await call('experimentalFeature/list',params);if(!Array.isArray(page?.data))throw new Error('feature list invalid');
for(const feature of page.data)if(denied.includes(feature.name))observed.set(feature.name,feature.enabled);cursor=page.nextCursor;
if(++pages>10)throw new Error('feature pagination overflow');}while(cursor!==null);
for(const name of denied)if(observed.get(name)!==false)throw new Error('native feature enabled: '+name);
const mcp=await call('mcpServerStatus/list',{threadId:started.thread.id,limit:100,detail:'toolsAndAuthOnly'});
if(!Array.isArray(mcp?.data)||mcp.data.length!==0||mcp.nextCursor!==null)throw new Error('native MCP isolation mismatch');
console.log('CODEX_NATIVE_THREAD_POLICY_PASS; no turn/start, no model call');stop();setTimeout(()=>process.exit(0),250);
})().catch(error=>{console.error(error.message);stop();setTimeout(()=>process.exit(1),250)});""".replace('__DENIED__', json.dumps(codex_denied_features()))
            native = subprocess.run([
                'docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=67108864',
                '-v', volumes['native'] + ':/native', '-v', volumes['workspace'] + ':/workspace:ro',
                '--entrypoint', 'node', image, '-e', native_probe,
            ], capture_output=True, text=True, timeout=20)
            assert native.returncode == 0, 'Codex native policy probe failed: ' + native.stderr.strip()[-256:]
            assert native.stdout.strip() == 'CODEX_NATIVE_THREAD_POLICY_PASS; no turn/start, no model call'
            run('docker', 'run', '-d', '--name', container, '--network', 'none', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--cpus', '1', '--memory', '1g',
                '--pids-limit', '128', '--tmpfs', '/tmp:rw,noexec,nosuid,size=67108864',
                *mounts, image, '--config', '/config/node.json')
            probe = """const https=require('node:https'),fs=require('node:fs');
const node=JSON.parse(fs.readFileSync('/config/node.json')).nodeId;
https.get({hostname:'127.0.0.1',port:18443,path:'/v1/identity',
ca:fs.readFileSync('/config/ca.pem')},r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{
const v=JSON.parse(d); const capabilities=Object.values(v.capabilities||{});
if(r.statusCode!==200||v.nodeId!==node||v.adapter.kind!=='codex'||v.adapter.version!=='0.153.4'||capabilities.length!==7||capabilities.some(x=>x!=='verified'))process.exit(1);
console.log(JSON.stringify({node:v.nodeId,epoch:v.identityEpoch,adapter:v.adapter,capabilities:v.capabilities}));});}).on('error',()=>process.exit(1));"""
            deadline = time.monotonic() + 30
            while True:
                try:
                    before = json.loads(run('docker', 'exec', container, 'node', '-e', probe))
                    break
                except (subprocess.CalledProcessError, RuntimeError) as error:
                    if time.monotonic() >= deadline:
                        captured = subprocess.run(['docker', 'logs', container], capture_output=True, text=True)
                        logs = (captured.stdout + captured.stderr)[-4000:]
                        state = subprocess.run([
                            'docker', 'run', '--rm', '-v', volumes['state'] + ':/state:ro',
                            '--entrypoint', '/bin/sh', image, '-c',
                            "find /state -maxdepth 3 -type f -printf '%P\\n' | sort",
                        ], capture_output=True, text=True)
                        raise RuntimeError('Harness identity probe did not become ready: ' + logs +
                                           ' durable files: ' + state.stdout.strip()) from error
                    time.sleep(1)
            assert run('docker', 'exec', container, '/opt/codex/node_modules/.bin/codex', '--version') == 'codex-cli 0.153.4'
            ledger_probe = """const fs=require('node:fs');
const state=JSON.parse(fs.readFileSync('/state/codex/native-mapping.json'));
if(state.schemaVersion!==2||Object.keys(state.attempts||{}).length!==0||Object.keys(state.dialogs||{}).length!==0)process.exit(1);
console.log('CODEX_EMPTY_DURABLE_DISPATCH_LEDGER_PASS');"""
            assert run('docker', 'exec', container, 'node', '-e', ledger_probe) == \
                'CODEX_EMPTY_DURABLE_DISPATCH_LEDGER_PASS'
            run('docker', 'exec', container, '/opt/codex/node_modules/.bin/codex', 'app-server',
                'generate-json-schema', '--out', '/state/schema-contract')
            schema_probe = """const fs=require('node:fs'),crypto=require('node:crypto');
const root='/state/schema-contract/'; const out={};
for(const name of ['ClientRequest.json','ServerNotification.json','ServerRequest.json'])
out[name]=crypto.createHash('sha256').update(fs.readFileSync(root+name)).digest('hex');
console.log(JSON.stringify(out));"""
            schemas = json.loads(run('docker', 'exec', container, 'node', '-e', schema_probe))
            assert schemas == {
                'ClientRequest.json': '25bc001b5dfe3b35785597b8f9ad9e5aaf7e437331fa9921f041c9e0e03fc9f3',
                'ServerNotification.json': 'b3e76cf11842f3e8b3270c05e000212b56eabafb0152fc38e8f920e2ef902991',
                'ServerRequest.json': '31f580ad468fbd18766eb7adb12744be4e3790e3357b58bd4413c0108c4f65d0',
            }, 'Codex app-server schema pin changed'
            run('docker', 'restart', container)
            deadline = time.monotonic() + 30
            while True:
                try:
                    after = json.loads(run('docker', 'exec', container, 'node', '-e', probe))
                    assert before == after, 'Harness identity changed on restart'
                    break
                except (subprocess.CalledProcessError, RuntimeError, AssertionError) as error:
                    if time.monotonic() >= deadline:
                        captured = subprocess.run(['docker', 'logs', container], capture_output=True, text=True)
                        logs = (captured.stdout + captured.stderr)[-4000:]
                        raise RuntimeError('Harness identity probe did not recover after restart: ' + logs) from error
                    time.sleep(1)
            info = json.loads(run('docker', 'inspect', container))[0]
            assert info['Config']['User'] == '10001:10001' and info['HostConfig']['ReadonlyRootfs']
            assert info['HostConfig']['NetworkMode'] == 'none'
            assert info['HostConfig']['PidsLimit'] == 128
            assert run('docker', 'exec', container, 'stat', '-c', '%u:%g:%a:%F',
                       '/harness-tool-runner') == '0:0:555:regular file'
            workspaces = [item for item in info['Mounts'] if item.get('Destination') == '/workspace']
            assert len(workspaces) == 1 and workspaces[0].get('RW') is True
            print('CODEX_CONTAINER_NATIVE_POLICY_TLS_AUTH_FREE_EMPTY_LEDGER_RESTART_PASS; zero turns, no model calls', flush=True)
        finally:
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for volume in created_volumes:
                subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)



def main():
    if not __debug__:
        raise RuntimeError('optimized Python is unsupported because smoke assertions must remain enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--openssl', help='OpenSSL 3 executable used for disposable test certificates')
    args = parser.parse_args()
    assert run('docker', 'image', 'inspect', '--format', '{{.Config.User}}', args.image) == '10001:10001'
    missing = subprocess.run(
        ['docker', 'run', '--rm', '--network', 'none', '--read-only', args.image],
        capture_output=True,
    )
    assert missing.returncode == 1, 'missing mounted config must fail closed'
    codex_smoke(args.image, args.openssl)


if __name__ == '__main__':
    main()
