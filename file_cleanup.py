#!/usr/bin/env python3
"""
File Cleanup Tool - 웹 브라우저 기반 미사용 파일 정리 도구
Windows Last Access Time을 이용하여 오래 사용하지 않은 파일을 찾아 삭제합니다.
사용법: python file_cleanup.py
브라우저: http://localhost:8080
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import webbrowser

SCAN_ROOT = os.getcwd()
PORT = 8080
MIN_SIZE_BYTES = 1_000_000  # 기본 최소 1MB 이상만 스캔

scan_result = {"files": [], "status": "idle", "scanned": 0, "errors": 0}
scan_lock = threading.Lock()

SKIP_DIRS = {"$RECYCLE.BIN", "System Volume Information", ".claude"}


def human_size(nbytes):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


def scan_directory(root):
    global scan_result
    with scan_lock:
        scan_result = {
            "files": [], "status": "scanning", "scanned": 0, "errors": 0,
            "found": 0, "current_dir": "", "start_time": time.time(),
        }

    files = []
    scanned = 0
    errors = 0
    found = 0

    def _walk(path):
        nonlocal scanned, errors, found
        with scan_lock:
            scan_result["current_dir"] = path
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name in SKIP_DIRS:
                                continue
                            _walk(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            stat = entry.stat()
                            if stat.st_size >= MIN_SIZE_BYTES:
                                files.append({
                                    "path": entry.path,
                                    "name": entry.name,
                                    "dir": os.path.dirname(entry.path),
                                    "size": stat.st_size,
                                    "size_h": human_size(stat.st_size),
                                    "atime": stat.st_atime,
                                    "atime_s": datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M"),
                                    "mtime": stat.st_mtime,
                                    "mtime_s": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                                    "ext": os.path.splitext(entry.name)[1].lower(),
                                })
                                found += 1
                            scanned += 1
                            if scanned % 100 == 0:
                                with scan_lock:
                                    scan_result["scanned"] = scanned
                                    scan_result["found"] = found
                    except (PermissionError, OSError):
                        errors += 1
        except (PermissionError, OSError):
            errors += 1

    _walk(root)
    files.sort(key=lambda f: f["atime"])

    with scan_lock:
        scan_result = {
            "files": files,
            "status": "done",
            "scanned": scanned,
            "errors": errors,
            "found": found,
            "total_size": sum(f["size"] for f in files),
            "total_size_h": human_size(sum(f["size"] for f in files)),
        }


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>File Cleanup Tool</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Segoe UI',sans-serif; background:#1a1a2e; color:#e0e0e0; }
  .header { background:#16213e; padding:16px 24px; border-bottom:1px solid #0f3460; display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
  .header h1 { font-size:20px; color:#e94560; flex-shrink:0; }
  .stats { display:flex; gap:16px; font-size:13px; color:#aaa; }
  .stats span { background:#0f3460; padding:4px 10px; border-radius:4px; }
  .stats .accent { color:#e94560; font-weight:bold; }
  .controls { padding:12px 24px; background:#16213e; border-bottom:1px solid #0f3460; display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
  .controls label { font-size:12px; color:#888; }
  .controls input, .controls select { background:#1a1a2e; border:1px solid #333; color:#e0e0e0; padding:5px 8px; border-radius:4px; font-size:13px; }
  .controls input[type=text] { width:240px; }
  .controls input[type=number] { width:80px; }
  button { background:#e94560; color:#fff; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px; }
  button:hover { background:#c73e54; }
  button:disabled { background:#555; cursor:not-allowed; }
  button.scan-btn { background:#0f3460; }
  button.scan-btn:hover { background:#1a4a8a; }
  button.danger { background:#b91c1c; }
  button.danger:hover { background:#991b1b; }
  .table-wrap { overflow:auto; height:calc(100vh - 180px); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  thead { position:sticky; top:0; z-index:10; }
  th { background:#0f3460; padding:8px 10px; text-align:left; cursor:pointer; user-select:none; white-space:nowrap; }
  th:hover { background:#1a4a8a; }
  th .arrow { font-size:10px; margin-left:4px; }
  td { padding:6px 10px; border-bottom:1px solid #222; white-space:nowrap; }
  tr:hover { background:#1f2a44; }
  tr.selected { background:#2a1a2e; }
  .cb { width:16px; height:16px; accent-color:#e94560; cursor:pointer; }
  .size-col { text-align:right; font-family:monospace; }
  .date-col { font-family:monospace; color:#8ab4f8; }
  .date-old { color:#e94560; }
  .date-mid { color:#f5a623; }
  .path-col { color:#888; font-size:12px; max-width:400px; overflow:hidden; text-overflow:ellipsis; }
  .ext-col { color:#8ab4f8; }
  .footer { position:fixed; bottom:0; left:0; right:0; background:#16213e; border-top:1px solid #0f3460; padding:10px 24px; display:flex; justify-content:space-between; align-items:center; z-index:100; }
  .footer .sel-info { font-size:14px; }
  .footer .sel-size { color:#e94560; font-weight:bold; font-size:16px; }
  .progress-bar { width:100%; height:3px; background:#333; }
  .progress-bar .fill { height:100%; background:#e94560; transition:width 0.3s; }
  .loading { text-align:center; padding:60px; color:#888; font-size:16px; }
  .ext-badge { display:inline-block; background:#0f3460; padding:1px 6px; border-radius:3px; font-size:11px; }
  .sort-badge { display:inline-block; background:#e94560; color:#fff; width:15px; height:15px; border-radius:50%; text-align:center; font-size:9px; line-height:15px; margin-left:2px; vertical-align:middle; }
  .scan-progress { display:flex; flex-direction:column; align-items:center; gap:20px; padding:48px 24px; }
  .spinner { width:48px; height:48px; border:4px solid #333; border-top:4px solid #e94560; border-radius:50%; animation:spin 1s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .scan-stats { display:flex; flex-direction:column; gap:6px; min-width:360px; }
  .scan-stat-row { display:flex; justify-content:space-between; padding:8px 14px; background:#16213e; border-radius:4px; font-size:14px; }
  .scan-stat-row b { color:#e94560; font-family:monospace; }
  .scan-current-dir { color:#8ab4f8; font-size:12px; max-width:500px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; text-align:center; padding:4px 8px; background:#16213e; border-radius:4px; }
  .progress-bar.indeterminate .fill { width:30% !important; animation:indeterminate 1.5s ease-in-out infinite; }
  @keyframes indeterminate { 0%{margin-left:0} 50%{margin-left:70%} 100%{margin-left:0} }
  button.clear-sort { background:#333; font-size:11px; padding:4px 10px; }
  button.clear-sort:hover { background:#555; }
  th .sort-info { white-space:nowrap; }
</style>
</head>
<body>

<div class="header">
  <h1>File Cleanup Tool</h1>
  <div class="stats">
    <span>Total: <b class="accent" id="totalFiles">-</b> files</span>
    <span>Size: <b class="accent" id="totalSize">-</b></span>
    <span>Scan: <b id="scanStatus">idle</b></span>
  </div>
  <button class="scan-btn" id="btnScan" onclick="startScan()">Scan</button>
</div>

<div class="controls">
  <div>
    <label>Search path/name</label><br>
    <input type="text" id="filterText" placeholder="search..." oninput="applyFilters()">
  </div>
  <div>
    <label>Extension</label><br>
    <select id="filterExt" onchange="applyFilters()">
      <option value="">All</option>
    </select>
  </div>
  <div>
    <label>Min size (MB)</label><br>
    <input type="number" id="filterMinSize" value="1" min="0" oninput="applyFilters()">
  </div>
  <div>
    <label>Accessed before</label><br>
    <input type="text" id="filterDate" placeholder="YYYY-MM-DD" oninput="applyFilters()">
  </div>
  <div style="margin-left:auto; display:flex; gap:8px; align-items:center;">
    <span style="font-size:11px; color:#666;">Shift+Click: multi-sort</span>
    <button class="clear-sort" onclick="clearSort()">Clear Sort</button>
    <button onclick="selectAll()">Select All Visible</button>
    <button onclick="deselectAll()">Deselect All</button>
  </div>
</div>

<div class="progress-bar" id="progressBar"><div class="fill" id="progressFill" style="width:0%"></div></div>

<div class="table-wrap" id="tableWrap">
  <div id="progressPanel">
    <div class="scan-progress">
      <div class="spinner" id="spinner" style="display:none"></div>
      <div class="scan-stats" id="scanStats" style="display:none">
        <div class="scan-stat-row"><span>Elapsed</span><b id="elapsed">0:00</b></div>
        <div class="scan-stat-row"><span>Files scanned</span><b id="scannedCount">0</b></div>
        <div class="scan-stat-row"><span>Large files found</span><b id="foundCount">0</b></div>
        <div class="scan-stat-row"><span>Scan rate</span><b id="scanRate">-</b></div>
        <div class="scan-stat-row"><span>Errors</span><b id="errorCount">0</b></div>
      </div>
      <div class="scan-current-dir" id="currentDir" style="display:none">-</div>
      <div class="loading" id="loadingMsg">Click "Scan" to start scanning...</div>
    </div>
  </div>
  <table id="fileTable" style="display:none">
    <thead>
      <tr>
        <th style="width:30px"><input type="checkbox" class="cb" id="checkAll" onchange="toggleAll(this)"></th>
        <th onclick="sortBy('name',event)">File Name <span class="sort-info" id="arrow_name"></span></th>
        <th onclick="sortBy('ext',event)">Ext <span class="sort-info" id="arrow_ext"></span></th>
        <th onclick="sortBy('size',event)">Size <span class="sort-info" id="arrow_size"></span></th>
        <th onclick="sortBy('atime',event)">Last Access <span class="sort-info" id="arrow_atime"></span></th>
        <th onclick="sortBy('mtime',event)">Modified <span class="sort-info" id="arrow_mtime"></span></th>
        <th onclick="sortBy('dir',event)">Directory <span class="sort-info" id="arrow_dir"></span></th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<div class="footer">
  <div class="sel-info">
    Selected: <b id="selCount">0</b> files
    (<span class="sel-size" id="selSize">0 B</span>)
  </div>
  <button class="danger" id="btnDelete" onclick="deleteSelected()" disabled>Delete Selected</button>
</div>

<script>
let allFiles = [];
let filteredFiles = [];
let selected = new Set();
let sortKeys = [];
let pollTimer = null;
let scanStartTime = null;
let elapsedTimer = null;

function startScan() {
  document.getElementById('btnScan').disabled = true;
  document.getElementById('scanStatus').textContent = 'scanning...';
  document.getElementById('progressPanel').style.display = '';
  document.getElementById('loadingMsg').style.display = 'none';
  document.getElementById('spinner').style.display = '';
  document.getElementById('scanStats').style.display = '';
  document.getElementById('currentDir').style.display = '';
  document.getElementById('fileTable').style.display = 'none';
  document.getElementById('progressBar').classList.add('indeterminate');
  selected.clear();
  updateSelInfo();

  scanStartTime = Date.now();
  if (elapsedTimer) clearInterval(elapsedTimer);
  elapsedTimer = setInterval(() => {
    let secs = Math.floor((Date.now() - scanStartTime) / 1000);
    let mins = Math.floor(secs / 60);
    let s = secs % 60;
    document.getElementById('elapsed').textContent = mins + ':' + String(s).padStart(2, '0');
  }, 1000);

  fetch('/api/scan', {method:'POST'}).then(r => r.json()).then(d => {
    pollTimer = setInterval(pollScan, 500);
  });
}

function pollScan() {
  fetch('/api/scan').then(r => r.json()).then(d => {
    document.getElementById('scannedCount').textContent = d.scanned.toLocaleString();
    document.getElementById('foundCount').textContent = (d.found || 0).toLocaleString();
    document.getElementById('errorCount').textContent = (d.errors || 0).toLocaleString();
    document.getElementById('scanStatus').textContent = d.status + ' (' + d.scanned.toLocaleString() + ')';

    if (d.current_dir) {
      let dir = d.current_dir;
      if (dir.length > 70) dir = '...' + dir.slice(-67);
      document.getElementById('currentDir').textContent = dir;
    }

    if (scanStartTime && d.scanned > 0) {
      let elapsed = (Date.now() - scanStartTime) / 1000;
      let rate = Math.round(d.scanned / elapsed);
      document.getElementById('scanRate').textContent = rate.toLocaleString() + ' files/sec';
    }

    if (d.status === 'done') {
      clearInterval(pollTimer);
      if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
      allFiles = d.files;
      document.getElementById('totalFiles').textContent = d.files.length.toLocaleString();
      document.getElementById('totalSize').textContent = d.total_size_h;
      document.getElementById('scanStatus').textContent = 'done (' + d.scanned.toLocaleString() + ' scanned)';
      document.getElementById('btnScan').disabled = false;
      document.getElementById('progressBar').classList.remove('indeterminate');
      document.getElementById('progressFill').style.width = '100%';
      buildExtFilter();
      applyFilters();
      document.getElementById('progressPanel').style.display = 'none';
      document.getElementById('fileTable').style.display = '';
      setTimeout(() => { document.getElementById('progressFill').style.width = '0%'; }, 1500);
    }
  });
}

function buildExtFilter() {
  let exts = {};
  allFiles.forEach(f => { exts[f.ext] = (exts[f.ext]||0) + 1; });
  let sorted = Object.entries(exts).sort((a,b) => b[1]-a[1]);
  let sel = document.getElementById('filterExt');
  sel.innerHTML = '<option value="">All (' + allFiles.length + ')</option>';
  sorted.forEach(([ext, cnt]) => {
    let o = document.createElement('option');
    o.value = ext;
    o.textContent = (ext || '(no ext)') + ' (' + cnt + ')';
    sel.appendChild(o);
  });
}

function applyFilters() {
  let text = document.getElementById('filterText').value.toLowerCase();
  let ext = document.getElementById('filterExt').value;
  let minMB = parseFloat(document.getElementById('filterMinSize').value) || 0;
  let minBytes = minMB * 1024 * 1024;
  let beforeDate = document.getElementById('filterDate').value;
  let beforeTs = beforeDate ? new Date(beforeDate + 'T23:59:59').getTime()/1000 : Infinity;

  filteredFiles = allFiles.filter(f => {
    if (text && !f.path.toLowerCase().includes(text)) return false;
    if (ext && f.ext !== ext) return false;
    if (f.size < minBytes) return false;
    if (f.atime > beforeTs) return false;
    return true;
  });

  doSort();
  renderTable();
}

function sortBy(col, event) {
  if (event && event.shiftKey) {
    let idx = sortKeys.findIndex(k => k.col === col);
    if (idx >= 0) {
      sortKeys[idx].asc = !sortKeys[idx].asc;
    } else {
      sortKeys.push({col: col, asc: (col === 'atime' || col === 'mtime')});
    }
  } else {
    let existing = sortKeys.length === 1 && sortKeys[0].col === col;
    if (existing) {
      sortKeys[0].asc = !sortKeys[0].asc;
    } else {
      sortKeys = [{col: col, asc: (col === 'atime' || col === 'mtime')}];
    }
  }
  updateSortArrows();
  doSort();
  renderTable();
}

function clearSort() {
  sortKeys = [];
  updateSortArrows();
  applyFilters();
}

function updateSortArrows() {
  document.querySelectorAll('.sort-info').forEach(a => a.innerHTML = '');
  sortKeys.forEach((k, i) => {
    let el = document.getElementById('arrow_' + k.col);
    if (el) {
      let badge = sortKeys.length > 1 ? '<span class="sort-badge">' + (i+1) + '</span>' : '';
      el.innerHTML = badge + '<span class="arrow">' + (k.asc ? '\u25B2' : '\u25BC') + '</span>';
    }
  });
}

function doSort() {
  if (sortKeys.length === 0) return;
  filteredFiles.sort((a, b) => {
    for (let k of sortKeys) {
      let va = a[k.col], vb = b[k.col];
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return k.asc ? -1 : 1;
      if (va > vb) return k.asc ? 1 : -1;
    }
    return 0;
  });
}

function dateClass(atime) {
  let now = Date.now() / 1000;
  let diff = now - atime;
  if (diff > 365*86400) return 'date-col date-old';
  if (diff > 180*86400) return 'date-col date-mid';
  return 'date-col';
}

function humanSize(bytes) {
  const units = ['B','KB','MB','GB','TB'];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length-1) { v /= 1024; i++; }
  return v.toFixed(1) + ' ' + units[i];
}

function renderTable() {
  let tbody = document.getElementById('tbody');
  // Render in chunks for performance
  let html = [];
  let limit = Math.min(filteredFiles.length, 5000);
  for (let i = 0; i < limit; i++) {
    let f = filteredFiles[i];
    let chk = selected.has(f.path) ? 'checked' : '';
    let selClass = selected.has(f.path) ? ' selected' : '';
    html.push(
      '<tr class="' + selClass + '" data-idx="'+i+'">' +
      '<td><input type="checkbox" class="cb" '+chk+' onchange="toggleFile(this,'+i+')"></td>' +
      '<td title="'+escHtml(f.name)+'">'+escHtml(f.name)+'</td>' +
      '<td class="ext-col"><span class="ext-badge">'+escHtml(f.ext)+'</span></td>' +
      '<td class="size-col">'+f.size_h+'</td>' +
      '<td class="'+dateClass(f.atime)+'">'+f.atime_s+'</td>' +
      '<td class="date-col">'+f.mtime_s+'</td>' +
      '<td class="path-col" title="'+escHtml(f.dir)+'">'+escHtml(f.dir)+'</td>' +
      '</tr>'
    );
  }
  tbody.innerHTML = html.join('');
  if (filteredFiles.length > 5000) {
    tbody.innerHTML += '<tr><td colspan="7" style="text-align:center;color:#888;padding:16px;">Showing 5,000 of ' + filteredFiles.length.toLocaleString() + ' files. Use filters to narrow down.</td></tr>';
  }
  updateSelInfo();
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function toggleFile(cb, idx) {
  let f = filteredFiles[idx];
  if (cb.checked) selected.add(f.path); else selected.delete(f.path);
  cb.closest('tr').classList.toggle('selected', cb.checked);
  updateSelInfo();
}

function toggleAll(cb) {
  let boxes = document.querySelectorAll('#tbody .cb');
  boxes.forEach((b, i) => {
    b.checked = cb.checked;
    let f = filteredFiles[i];
    if (f) {
      if (cb.checked) selected.add(f.path); else selected.delete(f.path);
      b.closest('tr').classList.toggle('selected', cb.checked);
    }
  });
  updateSelInfo();
}

function selectAll() {
  let limit = Math.min(filteredFiles.length, 5000);
  for (let i = 0; i < limit; i++) selected.add(filteredFiles[i].path);
  renderTable();
  document.getElementById('checkAll').checked = true;
}

function deselectAll() {
  selected.clear();
  renderTable();
  document.getElementById('checkAll').checked = false;
}

function updateSelInfo() {
  document.getElementById('selCount').textContent = selected.size;
  let totalBytes = 0;
  allFiles.forEach(f => { if (selected.has(f.path)) totalBytes += f.size; });
  document.getElementById('selSize').textContent = humanSize(totalBytes);
  document.getElementById('btnDelete').disabled = selected.size === 0;
}

function deleteSelected() {
  let cnt = selected.size;
  let totalBytes = 0;
  allFiles.forEach(f => { if (selected.has(f.path)) totalBytes += f.size; });
  if (!confirm('WARNING: Permanently delete ' + cnt + ' files (' + humanSize(totalBytes) + ')?\n\nThis cannot be undone!')) return;
  if (!confirm('Are you REALLY sure? This will permanently delete ' + cnt + ' files.')) return;

  document.getElementById('btnDelete').disabled = true;
  document.getElementById('btnDelete').textContent = 'Deleting...';

  fetch('/api/delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({paths: Array.from(selected)})
  }).then(r => r.json()).then(d => {
    alert('Deleted: ' + d.deleted + ' files\nFailed: ' + d.failed + ' files\nFreed: ' + d.freed_h);
    // Remove deleted files from allFiles
    let deletedSet = new Set(d.deleted_paths || []);
    allFiles = allFiles.filter(f => !deletedSet.has(f.path));
    selected.clear();
    document.getElementById('totalFiles').textContent = allFiles.length.toLocaleString();
    let ts = allFiles.reduce((s,f) => s+f.size, 0);
    document.getElementById('totalSize').textContent = humanSize(ts);
    applyFilters();
    document.getElementById('btnDelete').textContent = 'Delete Selected';
    document.getElementById('btnDelete').disabled = true;
  }).catch(e => {
    alert('Error: ' + e);
    document.getElementById('btnDelete').textContent = 'Delete Selected';
  });
}

// Auto-start scan on load
window.addEventListener('load', () => {
  sortKeys = [{col: 'atime', asc: true}];
  updateSortArrows();
  fetch('/api/config').then(r => r.json()).then(cfg => {
    document.getElementById('btnScan').textContent = 'Scan ' + cfg.scan_root;
    startScan();
  });
});
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default logging

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(HTML_PAGE)
        elif parsed.path == "/api/scan":
            with scan_lock:
                self._send_json(scan_result)
        elif parsed.path == "/api/config":
            self._send_json({"scan_root": SCAN_ROOT})
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            if scan_result["status"] != "scanning":
                t = threading.Thread(target=scan_directory, args=(SCAN_ROOT,), daemon=True)
                t.start()
            self._send_json({"ok": True})
        elif parsed.path == "/api/delete":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            paths = data.get("paths", [])

            deleted = 0
            failed = 0
            freed = 0
            deleted_paths = []

            for p in paths:
                try:
                    sz = os.path.getsize(p)
                    os.remove(p)
                    deleted += 1
                    freed += sz
                    deleted_paths.append(p)
                except Exception:
                    failed += 1

            self._send_json({
                "deleted": deleted,
                "failed": failed,
                "freed": freed,
                "freed_h": human_size(freed),
                "deleted_paths": deleted_paths,
            })
        else:
            self.send_error(404)


def main():
    print(f"=" * 60)
    print(f"  File Cleanup Tool")
    print(f"  Scan target: {SCAN_ROOT}")
    print(f"  Server: http://localhost:{PORT}")
    print(f"=" * 60)
    print(f"\nStarting server...")

    server = HTTPServer(("0.0.0.0", PORT), Handler)

    # Open browser
    def open_browser():
        time.sleep(0.5)
        webbrowser.open(f"http://localhost:{PORT}")

    threading.Thread(target=open_browser, daemon=True).start()

    print(f"Server running at http://localhost:{PORT}")
    print(f"Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
