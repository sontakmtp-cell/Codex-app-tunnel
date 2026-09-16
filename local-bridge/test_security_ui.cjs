// Security MCP App widget contract + optional browser host-loop test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const widgetPath = path.join(__dirname, 'security_scan_panel.html');
const html = fs.readFileSync(widgetPath, 'utf8');

function mustMatch(pattern, message) {
  assert.match(html, pattern, message);
}

function staticContract() {
  assert.ok(html.includes('<!doctype html>'), 'self-contained HTML resource');
  mustMatch(/ui\/notifications\/tool-result/, 'listens for MCP Apps tool results');
  mustMatch(/request\("tools\/call"/, 'uses MCP Apps tools/call first');
  mustMatch(/request\("ui\/message"/, 'uses MCP Apps ui/message first');
  mustMatch(/window\.openai[^\n]*callTool|window\.openai[\s\S]*callTool/, 'has callTool compatibility fallback');
  mustMatch(/sendFollowUpMessage/, 'has follow-up compatibility fallback');
  mustMatch(/security_start_scan/, 'starts a Security scan');
  mustMatch(/security_get_scan/, 'polls authoritative scan state');
  mustMatch(/security_cancel_scan/, 'cancels the same scan');
  mustMatch(/show_security_scan_panel/, 'reopens from authoritative panel state');
  mustMatch(/promptForStart/, 'button has an automatic workflow trigger');
  mustMatch(/const startPromise = client\.callTool\("security_start_scan"/, 'dispatches start without awaiting first');
  mustMatch(/messagePromise = client\.sendMessage\(promptForStart\(args\)\)/, 'dispatches the trigger in the click activation');
  mustMatch(/window\.openai\.sendFollowUpMessage\(\{ prompt: promptForStart\(args\)/, 'calls ChatGPT compatibility directly from the click stack');
  mustMatch(/attack_surface/, 'renders ChatGPT Deep attack-surface phase');
  mustMatch(/auth_data_flow/, 'renders ChatGPT Deep auth/data-flow phase');
  mustMatch(/injection_file_process_network_state/, 'renders ChatGPT Deep injection/file/process/network/state phase');
  mustMatch(/deduplicate/, 'renders ChatGPT Deep deduplication phase');
  mustMatch(/id="review-standard"/, 'Standard choice');
  mustMatch(/id="review-chatgpt-deep"/, 'ChatGPT Deep choice');
  mustMatch(/id="target-codebase"/, 'codebase target');
  mustMatch(/id="target-changes"/, 'changes target');
  mustMatch(/id="user-context"[^>]*maxlength="2000"/, 'bounded context input');
  mustMatch(/id="cancel-scan"/, 'cancel action');
  mustMatch(/id="finding-list"/, 'finding presentation');
  mustMatch(/data-theme="light"/, 'light theme tokens');
  assert.equal(html.toLowerCase().includes('native_'), false, 'unsupported native mode is not exposed');
  assert.equal(/<select[^>]+model/i.test(html), false, 'no model selector');
  assert.equal(html.includes('panel.html'), false, 'does not alter or embed the local control panel');
}

function javascriptSyntax() {
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map((match) => match[1]);
  assert.equal(scripts.length, 1, 'widget keeps one inline script');
  new vm.Script(scripts[0], { filename: widgetPath });
}

async function browserContract() {
  let chromium;
  try {
    const modulePath = process.env.PLAYWRIGHT_MODULE || path.join(process.env.USERPROFILE || '', '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
    ({ chromium } = require(modulePath));
  } catch (_) {
    return 'Playwright unavailable';
  }

  let browser;
  try {
    browser = await chromium.launch({ headless: true, executablePath: process.env.BRIDGE_BROWSER || undefined });
  } catch (_) {
    return 'Playwright browser unavailable';
  }

  const calls = [];
  let scan = null;
  let failMessage = false;
  const started = [];
  const wireEvents = [];
  const page = await browser.newPage({ viewport: { width: 900, height: 1100 } });
  const pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.exposeFunction('securityMcpHost', async (message) => {
    calls.push(message);
    if (message.method === 'ui/initialize') return { hostContext: { theme: 'dark' } };
    if (message.method === 'ui/message') {
      wireEvents.push('message-request');
      if (failMessage) throw new Error('simulated message failure');
      return {};
    }
    if (message.method !== 'tools/call') return {};
    const { name, arguments: args = {} } = message.params || {};
    if (name === 'show_security_scan_panel') return { structuredContent: { repo: { name: 'demo-repo', path: 'H:/AI/demo', branch: 'main', commit: 'abc123' }, supportedTargets: ['codebase', 'changes'], activeScan: scan, latestScan: scan && scan.status !== 'running' ? scan : null } };
    if (name === 'security_start_scan') {
      wireEvents.push('start-request');
      await new Promise((resolve) => setTimeout(resolve, 30));
      scan = { scanId: `scan-${started.length + 1}`, reviewMode: args.review_mode, target: args.target, status: 'running', phase: 'preflight', nextPhase: 'inventory', progress: 0, findingCounts: { total: 0 }, updatedAt: new Date().toISOString() };
      started.push({ ...args });
      wireEvents.push('start-response');
      return { structuredContent: scan };
    }
    if (name === 'security_get_scan') return { structuredContent: scan };
    if (name === 'security_cancel_scan') {
      scan = { ...scan, status: 'cancelled', updatedAt: new Date().toISOString() };
      return { structuredContent: scan };
    }
    throw new Error(`unexpected tool: ${name}`);
  });

  try {
    await page.setContent('<!doctype html><iframe id="app" title="Security MCP App" style="width:860px;height:1050px;border:0"></iframe>');
    await page.evaluate((source) => {
      const frame = document.getElementById('app');
      addEventListener('message', async (event) => {
        if (event.source !== frame.contentWindow || !event.data || !event.data.method) return;
        const message = event.data;
        try {
          const result = await window.securityMcpHost(message);
          event.source.postMessage({ jsonrpc: '2.0', id: message.id, result }, '*');
          if (message.method === 'tools/call') event.source.postMessage({ jsonrpc: '2.0', method: 'ui/notifications/tool-result', params: result }, '*');
        } catch (error) {
          event.source.postMessage({ jsonrpc: '2.0', id: message.id, error: { code: -32000, message: error.message } }, '*');
        }
      });
      frame.srcdoc = source;
    }, html);
    const frame = page.frameLocator('#app');
    await frame.getByRole('button', { name: 'Bắt đầu quét', exact: true }).waitFor();
    await frame.getByText('demo-repo', { exact: true }).waitFor();
    await frame.getByRole('button', { name: 'Bắt đầu quét', exact: true }).click();
    await frame.getByText('scan-1', { exact: true }).waitFor();
    try {
      await frame.getByText('Đã gửi lệnh tự động; ChatGPT đang tiếp tục scanId=scan-1.', { exact: true }).waitFor({ timeout: 5000 });
    } catch (error) {
      console.error('widget debug', { pageErrors, calls, body: await frame.locator('body').innerText() });
      throw error;
    }
    assert.equal(started.length, 1, 'one start call');
    assert.equal(started[0].review_mode, 'standard');
    assert.equal(started[0].target, 'codebase');
    assert.ok(started[0].request_id, 'start request_id');
    assert.ok(wireEvents.indexOf('message-request') < wireEvents.indexOf('start-response'), `automatic trigger must be dispatched before start response: ${wireEvents.join(',')}`);
    const startMessage = calls.find((call) => call.method === 'ui/message');
    assert.ok(startMessage, 'automatic workflow trigger message');
    assert.match(startMessage.params.content[0].text, /security_start_scan arguments=/, 'trigger carries exact start arguments');
    assert.match(startMessage.params.content[0].text, new RegExp(started[0].request_id), 'trigger carries the same request id');

    await frame.getByRole('button', { name: 'Hủy scan', exact: true }).click();
    await frame.locator('#live-status-label').getByText('Đã hủy', { exact: true }).waitFor();
    assert.equal(calls.filter((call) => call.method === 'tools/call' && call.params.name === 'security_cancel_scan').length, 1);
    assert.equal(calls.at(-1).params.arguments.scan_id, 'scan-1');

    failMessage = true;
    await frame.locator('#review-chatgpt-deep').click();
    await frame.getByRole('button', { name: 'Bắt đầu quét', exact: true }).click();
    await frame.getByText('scan-2', { exact: true }).waitFor();
    await frame.getByRole('button', { name: 'Gửi lại message', exact: true }).waitFor();
    assert.equal(started.length, 2, 'message failure does not start another scan');
    const scan2 = await frame.locator('#scan-id').textContent();
    await frame.getByRole('button', { name: 'Gửi lại message', exact: true }).click();
    assert.equal(started.length, 2, 'retrying ui/message keeps one start request');
    assert.equal(await frame.locator('#scan-id').textContent(), scan2, 'scanId remains immutable after message failure');
    const widgetFrame = page.frames().find((candidate) => candidate.parentFrame());
    assert.ok(widgetFrame, 'widget frame remains available on reopen');
    await widgetFrame.evaluate(() => window.__securityScanWidget.refresh());
    assert.equal(await frame.locator('#scan-id').textContent(), scan2, 'reopen refresh keeps authoritative scan');
    return 'Playwright DOM/MCP host loop';
  } finally {
    await browser.close();
  }
}

(async () => {
  staticContract();
  javascriptSyntax();
  const browserResult = await browserContract();
  console.log(`Security widget checks: PASS (${browserResult})`);
})().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
