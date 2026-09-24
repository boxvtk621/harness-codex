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
        legacy_node = '10000000-0000-4000-8000-000000000001'
        legacy_dialog = '30000000-0000-4000-8000-000000000001'
        legacy_request = '50000000-0000-4000-8000-000000000001'
        legacy_attempt = '60000000-0000-4000-8000-000000000001'
        legacy_key = '/'.join((legacy_node, legacy_dialog, legacy_request, legacy_attempt, '1'))
        legacy_mapping = {
            'schemaVersion': 2, 'processGeneration': 41,
            'attempts': {legacy_key: {
                'reference': {'NodeID': legacy_node, 'DialogID': legacy_dialog,
                              'RequestID': legacy_request, 'AttemptID': legacy_attempt,
                              'Generation': 1},
                'context': {'MessageID': '40000000-0000-4000-8000-000000000001',
                            'Sequence': 1},
                'policyHash': 'a' * 64, 'promptHash': 'b' * 64,
                'dispatchKind': 'start', 'threadId': 'legacy-thread-1',
                'turnId': 'legacy-turn-1', 'processGeneration': 41, 'state': 'terminal',
            }},
            'dialogs': {legacy_dialog: {
                'threadId': 'legacy-thread-1',
                'boundary': {'MessageID': '40000000-0000-4000-8000-000000000001',
                             'Sequence': 1},
                'policyHash': 'a' * 64,
            }},
        }
        legacy_auth = {'version': 1, 'revision': 7, 'state': 'unauthenticated',
                       'checkedAt': None, 'reasonCode': None, 'operation': None,
                       'receipts': {}}
        (root / 'legacy-native-mapping.json').write_text(
            json.dumps(legacy_mapping, separators=(',', ':')) + '\n')
        (root / 'legacy-provider-auth-v1.json').write_text(
            json.dumps(legacy_auth, separators=(',', ':')) + '\n')
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
                '&& cp /fixture/legacy-native-mapping.json /state/codex/native-mapping.json '
                '&& cp /fixture/legacy-provider-auth-v1.json /state/codex/provider-auth-v1.json '
                '&& chown -R 10001:10001 /config /state /auth /workspace /native '
                '&& chmod 600 /state/codex/native-mapping.json /state/codex/provider-auth-v1.json '
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
if(frame.error){const error=new Error(saved.method+' rpc '+String(frame.error.code)+': '+String(frame.error.message));
error.rpcCode=frame.error.code;error.rpcMessage=String(frame.error.message);saved.reject(error);}else saved.resolve(frame.result);}});
const call=(method,params)=>new Promise((resolve,reject)=>{const id=++next,timer=setTimeout(()=>{pending.delete(String(id));reject(new Error('timeout'))},10000);
pending.set(String(id),{method,resolve:value=>{clearTimeout(timer);resolve(value)},reject:error=>{clearTimeout(timer);reject(error)}});
child.stdin.write(JSON.stringify({id,method,params})+'\n');});
const notify=(method,params)=>child.stdin.write(JSON.stringify({method,params})+'\n');
(async()=>{const initialized=await call('initialize',{clientInfo:{name:'harness-codex-smoke',title:'Harness Codex smoke',version:'0.155.1'}});notify('initialized',{});
const userAgent=String(initialized?.userAgent||''),versionMatch=userAgent.match(/^[^/\s]+\/(\d+\.\d+\.\d+)(?:\s|$)/);
if(!versionMatch||versionMatch[1]!=='0.155.1')throw new Error('app-server version mismatch: '+userAgent);
let modelCursor=null;const allModels=[],modelCursors=new Set();for(let modelPages=0;;modelPages++){
if(modelPages>=10)throw new Error('model pagination overflow');const params={limit:100,includeHidden:true};if(modelCursor)params.cursor=modelCursor;
const page=await call('model/list',params);if(!Array.isArray(page?.data))throw new Error('model catalog invalid');allModels.push(...page.data);
const nextCursor=page.nextCursor===undefined?null:page.nextCursor;if(nextCursor===null)break;
if(typeof nextCursor!=='string'||nextCursor.length===0||modelCursors.has(nextCursor))throw new Error('model cursor invalid');
modelCursors.add(nextCursor);modelCursor=nextCursor;}
if(allModels.length===0)throw new Error('model catalog unavailable');
const uniqueIdentifiers=(items,label)=>{const seen=new Set();for(const value of items){if(typeof value!=='string'||value.trim()!==value||value.length===0||seen.has(value))throw new Error(label+' identifier invalid');seen.add(value);}return items;};
const modelCapabilities=allModels.map(model=>{if(!Array.isArray(model.supportedReasoningEfforts))throw new Error('model capability shape mismatch');
const reasoning=uniqueIdentifiers(model.supportedReasoningEfforts.map(item=>item?.reasoningEffort),'reasoning');
const serviceTiers=uniqueIdentifiers(Array.isArray(model.serviceTiers)?model.serviceTiers.map(item=>item?.id):[],'service tier');
const additionalSpeedTiers=uniqueIdentifiers(Array.isArray(model.additionalSpeedTiers)?model.additionalSpeedTiers:[],'speed tier');
const defaultReasoningEffort=model.defaultReasoningEffort??null,defaultServiceTier=model.defaultServiceTier??null;
if(defaultReasoningEffort!==null&&!reasoning.includes(defaultReasoningEffort))throw new Error('default reasoning effort mismatch');
if(defaultServiceTier!==null&&(typeof defaultServiceTier!=='string'||!serviceTiers.includes(defaultServiceTier)))throw new Error('default service tier mismatch');
return {id:model.id,model:model.model,isDefault:model.isDefault??null,reasoning,defaultReasoningEffort,serviceTiers,defaultServiceTier,additionalSpeedTiers};});
uniqueIdentifiers(modelCapabilities.map(model=>model.id),'model id');
uniqueIdentifiers(modelCapabilities.map(model=>model.model),'model');
const selectedModel=modelCapabilities[0].id;
const defaultModels=modelCapabilities.filter(model=>model.isDefault===true);
if(defaultModels.length!==1||!defaultModels[0].defaultReasoningEffort)throw new Error('native default model/effort unavailable');
const defaultStarted=await call('thread/start',{model:null,serviceTier:'default',cwd:'/workspace',approvalPolicy:'never',sandbox:'read-only',
developerInstructions:'deny-only container smoke',config:{features,mcp_servers:{},model_reasoning_effort:defaultModels[0].defaultReasoningEffort,web_search:'disabled'}});
if(!defaultStarted?.thread?.id)throw new Error('native null/default thread start failed');
const started=await call('thread/start',{model:selectedModel,cwd:'/workspace',approvalPolicy:'never',sandbox:'read-only',
developerInstructions:'deny-only container smoke',config:{features,mcp_servers:{},web_search:'disabled'}});
if(!started?.thread?.id||started.approvalPolicy!=='never'||started.sandbox?.type!=='readOnly'||started.sandbox?.networkAccess!==false)throw new Error('thread policy mismatch');
let activeThreadId=started.thread.id,threadResume;
try{const resumed=await call('thread/resume',{threadId:started.thread.id,model:selectedModel,cwd:'/workspace',approvalPolicy:'never',sandbox:'read-only',
developerInstructions:'deny-only container smoke',config:{features,mcp_servers:{},web_search:'disabled'}});
if(resumed?.thread?.id!==started.thread.id||resumed.approvalPolicy!=='never'||resumed.sandbox?.type!=='readOnly'||resumed.sandbox?.networkAccess!==false)throw new Error('thread resume policy mismatch');
activeThreadId=resumed.thread.id;threadResume={kind:'resumed',threadId:resumed.thread.id};}catch(error){
const expected='no rollout found for thread id '+started.thread.id;
if(error.rpcCode!==-32600||error.rpcMessage!==expected)throw error;
threadResume={kind:'zero-turn-no-rollout',rpcCode:error.rpcCode,message:error.rpcMessage};}
let cursor=null,pages=0;const observed=new Map();do{const params={threadId:activeThreadId,limit:100};if(cursor)params.cursor=cursor;
const page=await call('experimentalFeature/list',params);if(!Array.isArray(page?.data))throw new Error('feature list invalid');
for(const feature of page.data)if(denied.includes(feature.name))observed.set(feature.name,feature.enabled);cursor=page.nextCursor;
if(++pages>10)throw new Error('feature pagination overflow');}while(cursor!==null);
for(const name of denied)if(observed.get(name)!==false)throw new Error('native feature enabled: '+name);
const mcp=await call('mcpServerStatus/list',{threadId:activeThreadId,limit:100,detail:'toolsAndAuthOnly'});
if(!Array.isArray(mcp?.data)||mcp.data.length!==0||mcp.nextCursor!==null)throw new Error('native MCP isolation mismatch');
console.log(JSON.stringify({marker:'CODEX_NATIVE_CAPABILITY_PASS',version:'0.155.1',selectedModel,defaultThreadId:defaultStarted.thread.id,threadId:started.thread.id,threadResume,mcpServers:mcp.data.length,models:modelCapabilities,zeroTurns:true}));stop();setTimeout(()=>process.exit(0),250);
})().catch(error=>{console.error(error.message);stop();setTimeout(()=>process.exit(1),250)});""".replace('__DENIED__', json.dumps(codex_denied_features()))
            native = subprocess.run([
                'docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=67108864',
                '-v', volumes['native'] + ':/native', '-v', volumes['workspace'] + ':/workspace:ro',
                '--entrypoint', 'node', image, '-e', native_probe,
            ], capture_output=True, text=True, timeout=300)
            assert native.returncode == 0, 'Codex native policy probe failed: ' + native.stderr.strip()[-256:]
            native_capabilities = json.loads(native.stdout)
            native_thread_id = native_capabilities.get('threadId')
            native_resume = native_capabilities.get('threadResume')
            expected_resume_results = (
                {'kind': 'resumed', 'threadId': native_thread_id},
                {'kind': 'zero-turn-no-rollout', 'rpcCode': -32600,
                 'message': f'no rollout found for thread id {native_thread_id}'},
            )
            assert (native_capabilities.get('marker') == 'CODEX_NATIVE_CAPABILITY_PASS'
                    and native_capabilities.get('version') == '0.155.1'
                    and isinstance(native_thread_id, str) and native_thread_id
                    and isinstance(native_capabilities.get('defaultThreadId'), str)
                    and native_resume in expected_resume_results
                    and native_capabilities.get('mcpServers') == 0
                    and native_capabilities.get('zeroTurns') is True
                    and isinstance(native_capabilities.get('selectedModel'), str)
                    and any(model.get('id') == native_capabilities['selectedModel']
                            for model in native_capabilities.get('models', []))), \
                'Codex native capability evidence is invalid'
            print(json.dumps(native_capabilities, separators=(',', ':')), flush=True)
            run('docker', 'run', '-d', '--name', container, '--network', 'none', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--cpus', '1', '--memory', '1g',
                '--pids-limit', '128', '--tmpfs', '/tmp:rw,noexec,nosuid,size=67108864',
                *mounts, image, '--config', '/config/node.json')
            probe = """const https=require('node:https'),fs=require('node:fs');
const node=JSON.parse(fs.readFileSync('/config/node.json')).nodeId;
https.get({hostname:'127.0.0.1',port:18443,path:'/v1/identity',
ca:fs.readFileSync('/config/ca.pem')},r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{
const v=JSON.parse(d); const capabilities=Object.values(v.capabilities||{});
if(r.statusCode!==200||v.nodeId!==node||v.adapter.kind!=='codex'||v.adapter.version!=='0.155.1'||capabilities.length!==7||capabilities.some(x=>x!=='verified'))process.exit(1);
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
            assert run('docker', 'exec', container, '/opt/codex/node_modules/.bin/codex', '--version') == 'codex-cli 0.155.1'
            ledger_probe = """const fs=require('node:fs');
const state=JSON.parse(fs.readFileSync('/state/codex/native-mapping.json'));
const auth=JSON.parse(fs.readFileSync('/state/codex/provider-auth-v1.json'));
const attempts=Object.entries(state.attempts||{}),dialogs=Object.entries(state.dialogs||{});
if(state.schemaVersion!==2||attempts.length!==1||dialogs.length!==1||auth.version!==3||Object.keys(auth.receipts||{}).length!==0)process.exit(1);
console.log(JSON.stringify({processGeneration:state.processGeneration,attemptKey:attempts[0][0],attempt:attempts[0][1],dialogKey:dialogs[0][0],dialog:dialogs[0][1],authVersion:auth.version,authReceiptCount:Object.keys(auth.receipts||{}).length}));"""
            legacy_before = json.loads(run('docker', 'exec', container, 'node', '-e', ledger_probe))
            assert legacy_before['processGeneration'] == 42
            assert legacy_before['attemptKey'] == legacy_key
            assert legacy_before['attempt'] == legacy_mapping['attempts'][legacy_key]
            assert legacy_before['dialogKey'] == legacy_dialog
            assert legacy_before['dialog'] == legacy_mapping['dialogs'][legacy_dialog]
            run('docker', 'exec', container, '/opt/codex/node_modules/.bin/codex', 'app-server',
                'generate-json-schema', '--out', '/state/schema-contract')
            schema_probe = """const fs=require('node:fs'),crypto=require('node:crypto');
const root='/state/schema-contract/'; const out={};
for(const name of ['ClientRequest.json','ServerNotification.json','ServerRequest.json'])
out[name]=crypto.createHash('sha256').update(fs.readFileSync(root+name)).digest('hex');
console.log(JSON.stringify(out));"""
            schemas = json.loads(run('docker', 'exec', container, 'node', '-e', schema_probe))
            assert schemas == {
                'ClientRequest.json': '85d6d137bab416d9ad47982adf354d707713042da5d37f934d0b2ed386e53ca4',
                'ServerNotification.json': '0a1c81641a6a2f009d7d6e3e26e8b99e6522f34d749cb1a2d5f182bbc395fcc3',
                'ServerRequest.json': 'f339be472737a0003efa25fba2e6e6c9237e621cd065b6d6995c51256e9dc1fb',
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
            legacy_after_restart = json.loads(run('docker', 'exec', container, 'node', '-e', ledger_probe))
            assert legacy_after_restart['processGeneration'] == legacy_before['processGeneration'] + 1
            assert {key: value for key, value in legacy_after_restart.items() if key != 'processGeneration'} == \
                {key: value for key, value in legacy_before.items() if key != 'processGeneration'}
            info = json.loads(run('docker', 'inspect', container))[0]
            assert info['Config']['User'] == '10001:10001' and info['HostConfig']['ReadonlyRootfs']
            assert info['HostConfig']['NetworkMode'] == 'none'
            assert info['HostConfig']['PidsLimit'] == 128
            assert run('docker', 'exec', container, 'stat', '-c', '%u:%g:%a:%F',
                       '/harness-tool-runner') == '0:0:555:regular file'
            workspaces = [item for item in info['Mounts'] if item.get('Destination') == '/workspace']
            assert len(workspaces) == 1 and workspaces[0].get('RW') is True
            run('docker', 'rm', '-f', container)
            container = ''
            container = run('docker', 'run', '-d', '--name', prefix + '-recreated', '--network', 'none',
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--cpus', '1', '--memory', '1g', '--pids-limit', '128',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=67108864', *mounts, image,
                '--config', '/config/node.json')
            deadline = time.monotonic() + 30
            while True:
                try:
                    recreated = json.loads(run('docker', 'exec', container, 'node', '-e', probe))
                    assert before == recreated, 'Harness identity changed on recreate'
                    break
                except (subprocess.CalledProcessError, RuntimeError, AssertionError) as error:
                    if time.monotonic() >= deadline:
                        captured = subprocess.run(['docker', 'logs', container], capture_output=True, text=True)
                        logs = (captured.stdout + captured.stderr)[-4000:]
                        raise RuntimeError('Harness identity did not recover after recreate: ' + logs) from error
                    time.sleep(1)
            legacy_after_recreate = json.loads(run('docker', 'exec', container, 'node', '-e', ledger_probe))
            assert legacy_after_recreate['processGeneration'] == legacy_after_restart['processGeneration'] + 1
            assert {key: value for key, value in legacy_after_recreate.items() if key != 'processGeneration'} == \
                {key: value for key, value in legacy_before.items() if key != 'processGeneration'}
            print('CODEX_CONTAINER_NATIVE_POLICY_TLS_LEGACY_STATE_RESTART_RECREATE_PASS; zero turns, no model calls', flush=True)
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
