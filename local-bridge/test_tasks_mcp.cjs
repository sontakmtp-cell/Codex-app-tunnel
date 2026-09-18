// MCP 2026-07-28 Tasks wire workflow against the real stdio server and App Server runtime.
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { createInterface } = require('node:readline');
const assert = require('node:assert/strict');

const TASKS = 'io.modelcontextprotocol/tasks';
const UI = 'io.modelcontextprotocol/ui';
const base = path.resolve(__dirname, '.verification');
fs.mkdirSync(base, { recursive: true });
const temp = fs.mkdtempSync(path.join(base, 'tasks-mcp-'));
const project = path.join(temp, 'project');
const outside = path.join(temp, 'outside');
const state = path.join(temp, 'state');
fs.mkdirSync(project);
fs.mkdirSync(outside);
fs.writeFileSync(path.join(project, 'sleep_task.py'), 'import time\nprint("started", flush=True)\ntime.sleep(8)\nprint("done", flush=True)\n');
spawnSync('git', ['init', '-q'], { cwd: project, stdio: 'ignore' });
fs.writeFileSync(path.join(project, 'tracked.txt'), 'tracked\n');
spawnSync('git', ['add', '.'], { cwd: project, stdio: 'ignore' });
spawnSync('git', ['-c', 'user.name=MCP Test', '-c', 'user.email=mcp-test@example.invalid', 'commit', '-qm', 'fixture'], { cwd: project, stdio: 'ignore' });

const config = path.join(temp, 'config.json');
fs.writeFileSync(config, JSON.stringify({
  workspace_root: project,
  state_dir: state,
  external_read_roots: [outside],
  max_task_timeout_seconds: 30,
  tasks: {
    git_status: ['git', 'status', '--short'],
    sleep_task: ['python', '${PROJECT_ROOT}/sleep_task.py'],
  },
}));

function client(withTasks) {
  const child = spawn('uv', ['run', '--with', 'mcp==2.2.0', '--python', '3.13', path.join(__dirname, 'server.py'), '--config', config], {
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  child.stderr.on('data', () => {});
  const input = createInterface({ input: child.stdout });
  const pending = new Map();
  const subscriptions = new Map();
  let sequence = 0;
  input.on('line', (line) => {
    if (!line.trim()) return;
    const message = JSON.parse(line);
    if (message.method) {
      const subscriptionId = message.params?._meta?.['io.modelcontextprotocol/subscriptionId'];
      if (subscriptionId !== undefined && subscriptions.has(subscriptionId)) {
        subscriptions.get(subscriptionId).push(message);
      }
      return;
    }
    const waiter = pending.get(message.id);
    if (!waiter) return;
    clearTimeout(waiter.timer);
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(`${waiter.method}: ${JSON.stringify(message.error)}`));
    else waiter.resolve(message.result);
  });
  child.on('exit', () => {
    for (const waiter of pending.values()) waiter.reject(new Error('MCP server exited'));
    pending.clear();
  });
  const capabilities = { extensions: { [UI]: { mimeTypes: ['text/html;profile=mcp-app'] } } };
  if (withTasks) capabilities.extensions[TASKS] = {};
  const meta = {
    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientInfo': { name: 'tasks-wire-verification', version: '1' },
    'io.modelcontextprotocol/clientCapabilities': capabilities,
  };
  function rpc(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`MCP request timeout: ${method}`));
      }, 60000);
      pending.set(id, { resolve, reject, timer, method });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params: { ...params, _meta: meta } }) + '\n');
    });
  }
  function listen(taskIds) {
    const id = ++sequence;
    const messages = [];
    subscriptions.set(id, messages);
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0', id, method: 'subscriptions/listen',
      params: { notifications: { taskIds }, _meta: meta },
    }) + '\n');
    return { id, messages };
  }
  async function close() {
    input.close();
    if (child.exitCode !== null) return;
    child.stdin.end();
    await new Promise((resolve) => {
      const timer = setTimeout(() => { child.kill(); resolve(); }, 15000);
      child.once('exit', () => { clearTimeout(timer); resolve(); });
    });
  }
  return { rpc, listen, close };
}

async function waitForTask(mcp, taskId, predicate) {
  const seen = [];
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const state = await mcp.rpc('tasks/get', { taskId });
    seen.push(state.status);
    if (predicate(state)) return { state, seen };
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Task did not reach expected state: ${taskId}; seen=${seen.join(',')}`);
}

(async () => {
  let first;
  let second;
  let third;
  let legacy;
  try {
    first = client(true);
    const discovered = await first.rpc('server/discover');
    assert.ok(discovered.capabilities.extensions[TASKS]);
    const listed = await first.rpc('tools/list');
    const startTool = listed.tools.find((tool) => tool.name === 'start_task');
    assert.ok(startTool);
    assert.ok(startTool.inputSchema.properties.task_id);
    assert.ok(startTool.outputSchema);
    const diagnostics = await first.rpc('tools/call', { name: 'mcp_diagnostics', arguments: {} });
    assert.equal(diagnostics.structuredContent.tasks_support, true);
    assert.ok(diagnostics.structuredContent.server_capabilities.extensions[TASKS]);
    await assert.rejects(
      first.rpc('tasks/get', { taskId: 'missing-task' }),
      /-32602/,
    );

    const created = await first.rpc('tools/call', {
      name: 'start_task',
      arguments: { task_id: 'git_status', request_id: 'mcp-task-success-001', timeout_seconds: 30 },
    });
    assert.equal(created.resultType, 'task');
    assert.ok(created.taskId);
    assert.ok(['working', 'completed'].includes(created.status));

    const retried = await first.rpc('tools/call', {
      name: 'start_task',
      arguments: { task_id: 'git_status', request_id: 'mcp-task-success-001', timeout_seconds: 30 },
    });
    assert.equal(retried.resultType, 'task');
    assert.equal(retried.taskId, created.taskId);
    assert.equal((await first.rpc('tasks/update', { taskId: created.taskId, inputResponses: {} })).resultType, 'complete');
    const completed = await waitForTask(first, created.taskId, (state) => state.status === 'completed');
    assert.equal(completed.state.result.structuredContent.status, 'succeeded');
    assert.ok(completed.seen.includes('working') || created.status === 'completed');
    await first.close();
    first = null;

    second = client(true);
    const reconnected = await second.rpc('tasks/get', { taskId: created.taskId });
    assert.equal(reconnected.status, 'completed');
    assert.equal(reconnected.result.structuredContent.run_id, created.taskId);

    const cancellable = await second.rpc('tools/call', {
      name: 'start_task',
      arguments: { task_id: 'sleep_task', request_id: 'mcp-task-cancel-001', timeout_seconds: 20 },
    });
    assert.equal(cancellable.resultType, 'task');
    const runningFirst = await second.rpc('tasks/get', { taskId: cancellable.taskId });
    assert.equal(runningFirst.status, 'working');
    await new Promise((resolve) => setTimeout(resolve, 100));
    const runningSecond = await second.rpc('tasks/get', { taskId: cancellable.taskId });
    assert.equal(runningSecond.status, 'working');
    assert.equal(runningSecond.lastUpdatedAt, runningFirst.lastUpdatedAt);
    const subscription = second.listen([cancellable.taskId]);
    assert.equal((await second.rpc('tasks/cancel', { taskId: cancellable.taskId })).resultType, 'complete');
    const cancelled = await waitForTask(second, cancellable.taskId, (state) => state.status === 'cancelled');
    assert.notEqual(cancelled.state.lastUpdatedAt, runningFirst.lastUpdatedAt);
    assert.ok(cancelled.seen.includes('working') || cancellable.status === 'working');
    for (let attempt = 0; attempt < 40 && !subscription.messages.some((message) => message.method === 'notifications/tasks'); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.ok(subscription.messages.some((message) => message.method === 'notifications/subscriptions/acknowledged'));
    const taskNotification = subscription.messages.find((message) => message.method === 'notifications/tasks');
    assert.ok(taskNotification);
    assert.equal(taskNotification.params.taskId, cancellable.taskId);
    assert.equal(taskNotification.params.status, 'cancelled');
    assert.equal(taskNotification.params.resultType, undefined);
    assert.equal(taskNotification.params._meta['io.modelcontextprotocol/subscriptionId'], subscription.id);
    await second.close();
    second = null;

    third = client(true);
    const timed = await third.rpc('tools/call', {
      name: 'start_task',
      arguments: { task_id: 'sleep_task', request_id: 'mcp-task-timeout-001', timeout_seconds: 1 },
    });
    assert.equal(timed.resultType, 'task');
    const timedOut = await waitForTask(third, timed.taskId, (state) => state.status === 'completed');
    assert.equal(timedOut.state.result.structuredContent.status, 'timed_out');
    assert.equal(timedOut.state.result.isError, true);
    await third.close();
    third = null;

    legacy = client(false);
    await assert.rejects(
      legacy.rpc('tasks/get', { taskId: created.taskId }),
      /-32021/,
    );
    await assert.rejects(
      legacy.rpc('subscriptions/listen', { notifications: { taskIds: [created.taskId] } }),
      /-32021/,
    );
    const oldStart = await legacy.rpc('tools/call', {
      name: 'start_task',
      arguments: { task_id: 'git_status', request_id: 'legacy-task-001', timeout_seconds: 30 },
    });
    assert.equal(oldStart.resultType, 'complete');
    assert.ok(oldStart.structuredContent.run_id);
    assert.ok(!oldStart.taskId);
    const oldRead = await legacy.rpc('tools/call', {
      name: 'get_task_run',
      arguments: { run_id: oldStart.structuredContent.run_id },
    });
    assert.equal(oldRead.structuredContent.run_id, oldStart.structuredContent.run_id);
    console.log('MCP Tasks wire workflow: PASS; start/retry/update/get/cancel/timeout/reconnect/legacy all passed; temp:', temp);
  } finally {
    if (first) await first.close();
    if (second) await second.close();
    if (third) await third.close();
    if (legacy) await legacy.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
