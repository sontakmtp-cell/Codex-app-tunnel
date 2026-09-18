// Focused MCP Apps regression: a resource update with >200 running events
// must make the panel fetch each page once from its current cursor.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || path.join(process.env.USERPROFILE, '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'));

(async () => {
  const html = fs.readFileSync(path.join(__dirname, 'panel.html'), 'utf8');
  const runId = 'burst-run';
  const events = Array.from({ length: 250 }, (_, index) => ({
    stream: 'stdout',
    text: `event-${index}\n`,
  }));
  const getTaskCursors = [];
  const resourceStatuses = [];
  let activeRun = null;
  let subscriptionCount = 0;
  let browser;

  try {
    browser = await chromium.launch({
      headless: true,
      executablePath: process.env.BRIDGE_BROWSER || 'C:/Program Files/Google/Chrome/Application/chrome.exe',
    });
    const page = await browser.newPage({ viewport: { width: 900, height: 1000 } });
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.exposeFunction('hostRpc', async (message) => {
      const { method, params = {} } = message;
      if (method === 'ui/initialize') {
        return {
          protocolVersion: '2026-01-26',
          hostInfo: { name: 'cursor-regression-host', version: '1' },
          hostCapabilities: { serverTools: {} },
          hostContext: { theme: 'light' },
        };
      }
      if (method === 'resources/read') {
        resourceStatuses.push('running');
        return {
          contents: [{
            uri: params.uri,
            mimeType: 'application/json',
            text: JSON.stringify({
              task: { taskId: runId, status: 'working', eventCursor: events.length },
              run: {
                run_id: runId,
                task_id: 'burst_task',
                status: 'running',
                next_cursor: events.length,
                logs_available: true,
                truncated: false,
                stopping: false,
                timed_out: false,
              },
            }),
          }],
        };
      }
      if (method === 'subscriptions/listen') {
        subscriptionCount += 1;
        return {};
      }
      if (method !== 'tools/call') return {};
      const { name, arguments: args = {} } = params;
      if (name === 'project_info') {
        return { structuredContent: {
          workspace_root: 'C:/cursor-regression',
          git_repository: true,
          active_run_id: activeRun,
          runtime: { status: 'connected', mode: 'normal', commands_enabled: true, version: 'test' },
        } };
      }
      if (name === 'list_changes') return { structuredContent: { changes: [] } };
      if (name === 'list_tasks') return { structuredContent: { tasks: [{ task_id: 'burst_task' }] } };
      if (name === 'start_task') {
        activeRun = runId;
        return { structuredContent: { run_id: runId } };
      }
      if (name === 'get_task_run') {
        const cursor = Number(args.cursor || 0);
        const maxEvents = Number(args.max_events || 200);
        getTaskCursors.push(cursor);
        return { structuredContent: {
          run_id: runId,
          status: 'running',
          stopping: false,
          events: events.slice(cursor, cursor + maxEvents),
          next_cursor: Math.min(cursor + maxEvents, events.length),
          logs_available: true,
          truncated: false,
        } };
      }
      throw new Error(`unexpected tool: ${name}`);
    });

    await page.route('https://cursor-regression.test/**', (route) => route.fulfill({
      contentType: 'text/html',
      body: '<!doctype html><html><body><iframe id="app" title="MCP panel" style="width:860px;height:950px;border:0"></iframe></body></html>',
    }));
    await page.goto('https://cursor-regression.test/');
    await page.evaluate((panelHtml) => {
      const frame = document.getElementById('app');
      addEventListener('message', async (event) => {
        if (event.source !== frame.contentWindow || !event.data?.method || !event.data.id) return;
        const message = event.data;
        const target = event.source;
        try {
          const result = await window.hostRpc(message);
          if (message.method === 'subscriptions/listen') {
            const meta = { 'io.modelcontextprotocol/subscriptionId': message.id };
            target.postMessage({ jsonrpc: '2.0', method: 'notifications/subscriptions/acknowledged', params: { _meta: meta, notifications: { resources: true } } }, '*');
            setTimeout(() => target.postMessage({ jsonrpc: '2.0', method: 'notifications/resources/updated', params: { _meta: meta, uri: 'bridge://task/burst-run' } }, '*'), 25);
            return;
          }
          target.postMessage({ jsonrpc: '2.0', id: message.id, result }, '*');
        } catch (error) {
          target.postMessage({ jsonrpc: '2.0', id: message.id, error: { code: -32603, message: error.message } }, '*');
        }
      });
      frame.srcdoc = panelHtml;
    }, html);

    const frame = page.frameLocator('#app');
    await frame.getByRole('tab', { name: /Task & Terminal/ }).click();
    try {
      await frame.getByRole('button', { name: 'Chạy', exact: true }).waitFor();
    } catch (error) {
      console.error('panel debug:', errors, await page.locator('#app').contentFrame().locator('body').innerText().catch(() => 'no frame body'));
      throw error;
    }
    await frame.getByRole('button', { name: 'Chạy', exact: true }).click();
    await frame.getByText('event-249', { exact: false }).waitFor({ timeout: 15000 });

    const targetFrame = page.frames().find((child) => child.parentFrame());
    const metrics = await targetFrame.evaluate(() => window.__mcpPanelMetrics);
    const log = await frame.locator('[aria-label="Log task"]').innerText();
    for (let index = 0; index < events.length; index += 1) {
      const matches = log.match(new RegExp(`event-${index}\\b`, 'g')) || [];
      assert.equal(matches.length, 1, `event-${index} should appear once`);
    }
    assert.deepEqual(getTaskCursors, [0, 200]);
    assert.equal(subscriptionCount, 1);
    assert.equal(metrics.fallbackPolls, 0);
    assert.ok(metrics.subscriptionEvents >= 1);
    assert.deepEqual(resourceStatuses, ['running']);
    assert.deepEqual(errors, []);
    console.log('Task subscription cursor regression: PASS; 250 running events, cursors 0/200, fallback polling 0');
  } finally {
    if (browser) await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
