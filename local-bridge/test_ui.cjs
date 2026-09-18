// Real Chromium -> MCP Apps host harness -> actual MCP STDIO -> temporary project.
// This verifies the widget, not ChatGPT's hosted iframe or the OS command sandbox.
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { createInterface } = require('node:readline');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || path.join(process.env.USERPROFILE, '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'));

(async () => {
  const base = path.resolve(__dirname,'.verification');fs.mkdirSync(base,{recursive:true});
  const temp = fs.mkdtempSync(path.join(base,'ui-'));
  const project = path.join(temp,'project with spaces');fs.mkdirSync(project);
  const config = path.join(temp,'config.json');
  fs.writeFileSync(config,JSON.stringify({workspace_root:project,state_dir:path.join(temp,'state'),codex_executable:'C:/missing/codex.exe',tasks:{git_status:['git','status','--short']}}));
  const child=spawn('uv',['run','--with','mcp==2.2.0','--python','3.13',path.join(__dirname,'server.py'),'--config',config],{windowsHide:true,stdio:['pipe','pipe','pipe']});
  child.stderr.on('data',()=>{});
  const requests=new Map();let seq=0,browser;
  const input=createInterface({input:child.stdout});
  input.on('line',line=>{const m=JSON.parse(line);const p=requests.get(m.id);if(p){clearTimeout(p.timer);requests.delete(m.id);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}});
  function rpc(method,params={}){return new Promise((resolve,reject)=>{const id=++seq;const timer=setTimeout(()=>{requests.delete(id);reject(new Error('MCP request timeout: '+method));},60000);requests.set(id,{resolve,reject,timer});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');});}
  try {
    const modernMeta={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{name:'bridge-ui-verification',version:'2'},'io.modelcontextprotocol/clientCapabilities':{extensions:{'io.modelcontextprotocol/ui':{mimeTypes:['text/html;profile=mcp-app']}}}};
    const modern=(method,params={})=>rpc(method,{...params,_meta:modernMeta});
    const discovered=await modern('server/discover');assert.ok(discovered.supportedVersions.includes('2026-07-28'));assert.ok(discovered.capabilities.extensions['io.modelcontextprotocol/ui']);
    const mcpCall=async(name,args={})=>{const r=await modern('tools/call',{name,arguments:args});assert.ok(!r.isError,JSON.stringify(r.content));return r.structuredContent};
    const schema=await modern('tools/list');assert.equal(schema.tools.length,39);
    const diagnostics=await mcpCall('mcp_diagnostics');
    assert.equal(diagnostics.status,'ok');assert.ok(diagnostics.server_capabilities);assert.equal(diagnostics.apps_support,true);
    assert.equal(diagnostics.subscriptions_support,true);assert.equal(diagnostics.structured_output_support,true);
    assert.equal(diagnostics.protocol_version,'2026-07-28');assert.ok(diagnostics.client_capabilities);
    assert.equal(diagnostics.server_capabilities.tools.listChanged,true);
    assert.equal(diagnostics.server_capabilities.resources.subscribe,true);
    assert.ok(diagnostics.server_capabilities.extensions['io.modelcontextprotocol/ui']);
    assert.equal(diagnostics.resource_uri,'ui://local-bridge/control-panel-v2.html');
    assert.ok(!/["'](token|authorization|password|secret|credential|\.env)["']/i.test(JSON.stringify(diagnostics)));
    const info=await mcpCall('project_info');assert.equal(info.workspace_root.replaceAll('\\','/'),project.replaceAll('\\','/'));
    const malicious='<img src=x onerror="window.PWNED=true">\r\nKhầy\r\n';
    const change=await mcpCall('prepare_changes',{title:'Kiểm thử UI',edits:[{path:'xin chao.txt',content:malicious}],request_id:'ui-test-prepare'});
    assert.ok(!fs.existsSync(path.join(project,'xin chao.txt')));
    const resource=await modern('resources/read',{uri:'ui://local-bridge/control-panel-v2.html'});
    assert.equal(resource.contents[0].mimeType,'text/html;profile=mcp-app');
    browser=await chromium.launch({headless:true,executablePath:process.env.BRIDGE_BROWSER || 'C:/Program Files/Google/Chrome/Application/chrome.exe'});
    const page=await browser.newPage({viewport:{width:900,height:1000}});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.exposeFunction('mcpCall',async message=>modern(message.method,message.params));
    await page.route('https://bridge.test/**',route=>route.fulfill({contentType:'text/html',body:'<!doctype html><html><body><iframe id="app" title="MCP panel" style="width:860px;height:950px;border:0"></iframe></body></html>'}));
    await page.goto('https://bridge.test/');
    await page.evaluate(html=>{
      const frame=document.getElementById('app');
      addEventListener('message',async e=>{
        if(e.source!==frame.contentWindow || !e.data?.method || !e.data.id)return;
        const m=e.data;
        try{
          const result=m.method==='ui/initialize'?{protocolVersion:'2026-01-26',hostInfo:{name:'verification-host',version:'1'},hostCapabilities:{serverTools:{}},hostContext:{theme:'light'}}:await window.mcpCall(m);
          e.source.postMessage({jsonrpc:'2.0',id:m.id,result},'*');
        }catch(error){e.source.postMessage({jsonrpc:'2.0',id:m.id,error:{code:-32603,message:error.message}},'*');}
      });
      frame.srcdoc=html;
    },resource.contents[0].text);
    const frame=page.frameLocator('#app');
    await frame.getByRole('button',{name:'Normal (An toàn)',exact:true}).waitFor();
    await frame.getByRole('button',{name:'Turbo (Mở quyền)',exact:true}).waitFor();
    await frame.getByRole('tab',{name:/Workspace & Sơ đồ/}).click();
    await frame.locator('#panel-system').getByText(project.replaceAll('\\','/'),{exact:true}).waitFor();
    await frame.getByRole('tab',{name:/MCP Diagnostics/}).click();
    await frame.getByText('MCP Protocol Diagnostics',{exact:true}).waitFor();
    await frame.getByText('Python MCP SDK version',{exact:true}).waitFor();
    const copyButton=frame.getByRole('button',{name:'Copy diagnostics',exact:true});
    await copyButton.waitFor();await copyButton.click();
    await frame.getByRole('button',{name:/Copied|Copy failed/}).waitFor();
    await frame.getByRole('tab',{name:/Workspace & Sơ đồ/}).click();
    await frame.locator('#panel-system').getByText(project.replaceAll('\\','/'),{exact:true}).waitFor();
    await frame.getByRole('tab',{name:/Đợt sửa & Diff/}).click();
    await frame.getByRole('combobox').first().selectOption(change.change_id);
    await frame.getByRole('button',{name:'Áp dụng đợt sửa',exact:true}).waitFor();
    await frame.getByRole('button',{name:'Áp dụng đợt sửa',exact:true}).click();
    await frame.getByText('Đã áp dụng',{exact:true}).waitFor();
    assert.equal(fs.readFileSync(path.join(project,'xin chao.txt'),'utf8'),malicious);
    const targetFrame=page.frames().find(f=>f.parentFrame());
    assert.equal(await targetFrame.evaluate(()=>window.PWNED),undefined);
    assert.equal(await frame.locator('#diff img').count(),0);
    const output=path.resolve(__dirname,'../output/playwright');fs.mkdirSync(output,{recursive:true});
    await page.screenshot({path:path.join(output,'control-panel-applied.png'),fullPage:true});
    await frame.getByRole('button',{name:'Hoàn tác đợt sửa',exact:true}).click();
    await frame.getByRole('button',{name:'Hoàn tác ngay',exact:true}).click();
    await frame.getByText('Đã hoàn tác',{exact:true}).waitFor();
    assert.ok(!fs.existsSync(path.join(project,'xin chao.txt')));
    assert.equal((await mcpCall('apply_changes',{change_id:change.change_id,request_id:`ui-apply-${change.change_id}`})).status,'undone');
    if(!info.runtime.commands_enabled){
      await frame.getByRole('tab',{name:/Task & Terminal/}).click();
      assert.ok(await frame.getByRole('button',{name:'Chạy',exact:true}).isDisabled());
    }
    assert.deepEqual(errors,[]);
    const evidence=JSON.stringify({ui:'PASS',stdio:'PASS',preview_apply_undo:'PASS',xss:'PASS',commands_enabled:info.runtime.commands_enabled,chatgpt_host:'NOT_TESTED',project},null,2);
    fs.writeFileSync(path.join(temp,'result.json'),evidence);
    fs.writeFileSync(path.join(base,'ui-result.json'),evidence);
    console.log('UI/MCP integration: PASS; result:',path.join(temp,'result.json'));
  } finally {
    if(browser)await browser.close();
    child.stdin.end();
    await new Promise(resolve=>{if(child.exitCode!==null)return resolve();child.once('exit',resolve);setTimeout(()=>{child.kill();resolve();},10000).unref();});
    input.close();
  }
})().catch(e=>{console.error(e);process.exitCode=1;});
