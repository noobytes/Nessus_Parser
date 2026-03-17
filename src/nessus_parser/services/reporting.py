from __future__ import annotations

import csv
import html
import json
import re
from pathlib import Path

from nessus_parser.services.playbooks import get_playbook, list_playbook_plugin_ids
from nessus_parser.services.scans import get_plugin_details
from nessus_parser.services.validation import (
    get_latest_validation_results,
    get_validation_summary,
)


def _extract_underlying_items(trigger: str, stdout: str) -> list[str]:
    """For synthetic validation markers, extract the real items they represent.

    e.g. 'cbc_enabled' → actual CBC cipher names from the nmap output.
    Returns empty list if the trigger is not a known synthetic marker.
    """
    t = trigger.lower()
    if "cbc" in t:
        # Extract the specific CBC cipher algorithm names from nmap ssh2-enum-algos output
        found = re.findall(
            r'\b((?:aes(?:128|192|256)|3des|blowfish|cast128)-cbc)\b',
            stdout,
            re.IGNORECASE,
        )
        seen: set[str] = set()
        return [c.lower() for c in found if not (c.lower() in seen or seen.add(c.lower()))]  # type: ignore[func-returns-value]
    return []


def _extract_highlight_terms(stdout: str, playbook: dict) -> list[str]:
    """Return the specific strings in stdout that justify the validated verdict.

    Only includes what actually matched — version pattern captures and
    validated_if literal strings — so the report highlights precisely the
    evidence, nothing else.  Synthetic markers (e.g. CBC_ENABLED) are
    expanded into the actual underlying items they represent.
    """
    terms: list[str] = []
    stdout_lower = stdout.lower()

    version_rule = playbook.get("version_rule") or {}
    for pat in version_rule.get("version_patterns", []):
        try:
            m = re.search(pat, stdout, re.IGNORECASE)
            if m:
                term = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                if term:
                    terms.append(term)
        except re.error:
            pass

    for term in playbook.get("validated_if", []):
        if not term or term.lower() not in stdout_lower:
            continue
        underlying = _extract_underlying_items(term, stdout)
        if underlying:
            terms.extend(underlying)
        else:
            terms.append(term)

    seen2: set[str] = set()
    return [t for t in terms if not (t in seen2 or seen2.add(t))]  # type: ignore[func-returns-value]


def _relevant_lines(stdout: str, highlight_terms: list[str]) -> list[str]:
    """Return only the lines from stdout that contain at least one highlight term."""
    if not highlight_terms:
        return []
    lower_terms = [t.lower() for t in highlight_terms]
    return [
        line for line in stdout.splitlines()
        if any(lt in line.lower() for lt in lower_terms)
    ]


def build_plugin_report(db_path: Path, plugin_id: int, project_name: str | None = None) -> str:
    plugin = get_plugin_details(db_path, plugin_id)
    if plugin is None:
        return f"Plugin {plugin_id} not found in local database"

    lines = [
        f"plugin_id: {plugin[0]}",
        f"name: {plugin[1]}",
    ]

    summary = get_validation_summary(db_path, plugin_id, project_name=project_name)
    if not summary:
        lines.append("results: none")
        return "\n".join(lines)

    lines.append("summary:")
    for status, count in summary:
        lines.append(f"status\t{status}\tcount={count}")

    latest_results = get_latest_validation_results(db_path, plugin_id, project_name=project_name)
    lines.append(f"latest_results: {len(latest_results)}")
    for host, port, status, reason, analyst_note, command, executed_at, source in latest_results[:50]:
        lines.append(
            f"result\t{host}\tport={port}\tstatus={status}\treason={reason or '-'}\tnote={analyst_note or '-'}\tsource={source}\tat={executed_at}\tcommand={command}"
        )
    if len(latest_results) > 50:
        lines.append(f"... truncated {len(latest_results) - 50} additional results")
    return "\n".join(lines)


def export_plugin_report_csv(db_path: Path, plugin_id: int, output_path: Path, project_name: str | None = None) -> Path:
    latest_results = get_latest_validation_results(db_path, plugin_id, project_name=project_name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "port", "status", "reason", "analyst_note", "source", "executed_at", "command"])
        for row in latest_results:
            host, port, status, reason, analyst_note, command, executed_at, source = row[:8]
            writer.writerow([host, port, status, reason or "", analyst_note or "", source, executed_at, command])
    return output_path


def export_all_reports_csv(db_path: Path, output_path: Path, project_name: str | None = None) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plugin_ids = list_playbook_plugin_ids(db_path)
    with output_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "plugin_id",
                "plugin_name",
                "host",
                "port",
                "status",
                "reason",
                "analyst_note",
                "source",
                "executed_at",
                "command",
            ]
        )
        for plugin_id in plugin_ids:
            plugin = get_plugin_details(db_path, plugin_id)
            plugin_name = plugin[1] if plugin is not None else ""
            for host, port, status, reason, analyst_note, command, executed_at, source in get_latest_validation_results(db_path, plugin_id, project_name=project_name):
                writer.writerow(
                    [
                        plugin_id,
                        plugin_name,
                        host,
                        port,
                        status,
                        reason or "",
                        analyst_note or "",
                        source,
                        executed_at,
                        command,
                    ]
                )
    return output_path


def export_all_reports_html(db_path: Path, output_path: Path, project_name: str | None = None) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plugin_ids = list_playbook_plugin_ids(db_path)
    dataset: list[dict[str, object]] = []

    for plugin_id in plugin_ids:
        plugin = get_plugin_details(db_path, plugin_id)
        plugin_name = plugin[1] if plugin is not None else str(plugin_id)
        plugin_summary = "-"
        plugin_severity = "-"
        if plugin is not None:
            plugin_summary = plugin[4] or plugin[5] or plugin[6] or "-"
            plugin_severity = plugin[3] or "-"
        summary = get_validation_summary(db_path, plugin_id, project_name=project_name)
        latest_results = get_latest_validation_results(db_path, plugin_id, project_name=project_name)

        # Pick the first validated result as the evidence sample
        validated_sample = None
        for row in latest_results:
            if row[2] == "validated":
                stdout = (row[8] or "").strip()
                stderr = (row[9] or "").strip()
                playbook = get_playbook(db_path, plugin_id)
                output = stdout or stderr
                highlight_terms = (
                    _extract_highlight_terms(output, playbook)
                    if playbook else []
                )
                relevant = _relevant_lines(output, highlight_terms)
                validated_sample = {
                    "host": row[0],
                    "port": row[1],
                    "command": row[5],
                    "stdout": output,
                    "relevant_lines": relevant,
                    "highlight_terms": highlight_terms,
                }
                break

        dataset.append(
            {
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "plugin_summary": plugin_summary,
                "plugin_severity": plugin_severity,
                "summary": [{"status": status, "count": count} for status, count in summary],
                "validated_sample": validated_sample,
                "results": [
                    {
                        "host": row[0],
                        "port": row[1],
                        "status": row[2],
                        "reason": row[3] or "-",
                        "analyst_note": row[4] or "-",
                        "command": row[5],
                        "executed_at": row[6],
                        "source": row[7],
                    }
                    for row in latest_results
                ],
            }
        )

    report_title = f"Nessus Parser Report \u2014 {html.escape(project_name)}" if project_name else "Nessus Parser Report"
    output_path.write_text(
        ("""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>REPORT_TITLE_PLACEHOLDER</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: Georgia, serif; margin: 2rem; background: #f4efe6; color: #1f1a17; }
    h1, h2 { font-family: 'Trebuchet MS', sans-serif; }
    .toolbar { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; margin: 1rem 0 1.5rem; }
    .toolbar label { display: block; font: 0.8rem/1.2 'Trebuchet MS', sans-serif; text-transform: uppercase; letter-spacing: .04em; color: #6b5748; margin-bottom: 0.2rem; }
    .toolbar input, .toolbar select { width: 100%; padding: 0.5rem; border: 1px solid #cdbfa9; background: #fffdf8; }
    .plugin { background: #fffaf2; border: 1px solid #d8ccb8; padding: 1rem; margin: 0 0 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,.05); }
    .plugin details { margin-top: 0.75rem; }
    .plugin summary { cursor: pointer; font-family: 'Trebuchet MS', sans-serif; font-weight: 600; color: #5a4637; }
    .chips { display: flex; flex-wrap: wrap; gap: 0.45rem; margin: 0.75rem 0; padding: 0; list-style: none; }
    .chip { display: inline-block; padding: 0.2rem 0.55rem; border-radius: 999px; background: #efe3d0; border: 1px solid #d8ccb8; font: 0.8rem/1.2 'Trebuchet MS', sans-serif; }
    .chip.sev-1 { background: #f3e7b8; }
    .chip.sev-2 { background: #f7cf9c; }
    .chip.sev-3 { background: #efb1a8; }
    .chip.sev-4 { background: #c0392b; color: #fff; border-color: #a93226; }
    table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
    th, td { border: 1px solid #d8ccb8; padding: 0.45rem; vertical-align: top; text-align: left; }
    th { background: #efe3d0; }
    code { font-size: 0.85rem; white-space: pre-wrap; word-break: break-word; }
    ul { margin-top: 0.5rem; }
    .stats { margin: 1rem 0; font-family: 'Trebuchet MS', sans-serif; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
    .actions { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }
    .button { padding: 0.5rem 0.8rem; border: 1px solid #b9a88f; background: #e8dcc9; color: #2a211c; font: 0.85rem/1.2 'Trebuchet MS', sans-serif; cursor: pointer; }
    .group-title { font: 1.15rem/1.2 'Trebuchet MS', sans-serif; margin: 1.75rem 0 0.75rem; color: #5a4637; text-transform: uppercase; letter-spacing: 0.04em; }
    .evidence-toggle { display: inline-flex; align-items: center; gap: 0.4rem; margin-top: 0.85rem; cursor: pointer; font: 0.85rem/1.2 'Trebuchet MS', sans-serif; color: #3a5a8a; border: 1px solid #3a5a8a; padding: 0.25rem 0.6rem; background: #eef3fa; user-select: none; }
    .evidence-toggle .toggle-icon { font-size: 1rem; font-weight: 700; line-height: 1; }
    .evidence-box { display: none; margin-top: 0.5rem; border: 1px solid #ccc; background: #ffffff; color: #000000; font-family: 'Courier New', Courier, monospace; font-size: 0.82rem; padding: 0.85rem 1rem; white-space: pre-wrap; word-break: break-word; line-height: 1.55; }
    .evidence-box.visible { display: block; }
    .evidence-label { font: 0.78rem/1.2 'Trebuchet MS', sans-serif; color: #6b5748; margin-top: 0.85rem; margin-bottom: 0.25rem; text-transform: uppercase; letter-spacing: 0.04em; }
    .ev-highlight { color: #cc0000; font-weight: 700; }
    .full-output-toggle { font: 0.78rem/1.2 'Trebuchet MS', sans-serif; color: #888; cursor: pointer; margin-top: 0.5rem; display: inline-block; text-decoration: underline; }
    .full-output-box { display: none; margin-top: 0.4rem; border-top: 1px dashed #ccc; padding-top: 0.5rem; white-space: pre-wrap; word-break: break-word; color: #444; }
  </style>
</head>
<body>
  <h1>REPORT_TITLE_PLACEHOLDER</h1>
  <p>Latest result per plugin / host / port.</p>
  <div class="toolbar">
    <div><label for="pluginFilter">Plugin</label><input id="pluginFilter" placeholder="84502 or HSTS"></div>
    <div><label for="findingFilter">Finding</label><input id="findingFilter" placeholder="certificate or openssh"></div>
    <div><label for="severityFilter">Severity</label><select id="severityFilter"><option value="">All</option><option value="1">Low</option><option value="2">Medium</option><option value="3">High</option><option value="4">Critical</option></select></div>
    <div><label for="statusFilter">Status</label><select id="statusFilter"><option value="">All</option></select></div>
    <div><label for="hostFilter">Host</label><input id="hostFilter" placeholder="host or domain"></div>
    <div><label for="sourceFilter">Source</label><select id="sourceFilter"><option value="">All</option><option value="automation">automation</option><option value="manual">manual</option></select></div>
    <div><label for="tpOnly">Focus</label><select id="tpOnly"><option value="">All results</option><option value="validated">True positives only</option></select></div>
  </div>
  <div class="stats">
    <div id="stats"></div>
    <div class="actions">
      <button class="button" id="exportCsv">Export Filtered CSV</button>
    </div>
  </div>
  <div id="plugins"></div>
  <script>
    const DATA = 
"""
        + json.dumps(dataset)
        + """
;
    const pluginFilter = document.getElementById('pluginFilter');
    const findingFilter = document.getElementById('findingFilter');
    const severityFilter = document.getElementById('severityFilter');
    const statusFilter = document.getElementById('statusFilter');
    const hostFilter = document.getElementById('hostFilter');
    const sourceFilter = document.getElementById('sourceFilter');
    const tpOnly = document.getElementById('tpOnly');
    const stats = document.getElementById('stats');
    const container = document.getElementById('plugins');
    const exportCsv = document.getElementById('exportCsv');
    let LAST_ROWS = [];
    let LAST_PLUGIN_COUNT = 0;

    const statuses = [...new Set(DATA.flatMap(p => p.results.map(r => r.status)))].sort();
    for (const status of statuses) {
      const opt = document.createElement('option');
      opt.value = status;
      opt.textContent = status;
      statusFilter.appendChild(opt);
    }

    function render() {
      const pluginNeedle = pluginFilter.value.trim().toLowerCase();
      const findingNeedle = findingFilter.value.trim().toLowerCase();
      const severityNeedle = severityFilter.value;
      const statusNeedle = statusFilter.value;
      const hostNeedle = hostFilter.value.trim().toLowerCase();
      const sourceNeedle = sourceFilter.value;
      const tpOnlyNeedle = tpOnly.value;

      let renderedPlugins = 0;
      let renderedRows = 0;
      const groupedSections = {"4": [], "3": [], "2": [], "1": [], "-": []};
      LAST_ROWS = [];

      DATA.forEach(plugin => {
        const pluginMatch = !pluginNeedle || `${plugin.plugin_id} ${plugin.plugin_name} ${plugin.plugin_summary}`.toLowerCase().includes(pluginNeedle);
        const findingMatch = !findingNeedle || `${plugin.plugin_name} ${plugin.plugin_summary}`.toLowerCase().includes(findingNeedle);
        const severityMatch = !severityNeedle || String(plugin.plugin_severity) === severityNeedle;
        let rows = plugin.results.filter(row => {
          if (!pluginMatch) return false;
          if (!findingMatch) return false;
          if (!severityMatch) return false;
          if (tpOnlyNeedle && row.status !== tpOnlyNeedle) return false;
          if (statusNeedle && row.status !== statusNeedle) return false;
          if (hostNeedle && !row.host.toLowerCase().includes(hostNeedle)) return false;
          if (sourceNeedle && row.source !== sourceNeedle) return false;
          return true;
        });
        if (!rows.length) return;
        renderedPlugins += 1;
        renderedRows += rows.length;
        for (const row of rows) {
          LAST_ROWS.push({
            plugin_id: plugin.plugin_id,
            plugin_name: plugin.plugin_name,
            plugin_summary: plugin.plugin_summary,
            plugin_severity: plugin.plugin_severity,
            ...row,
          });
        }
        const summary = Object.entries(rows.reduce((acc, row) => {
          acc[row.status] = (acc[row.status] || 0) + 1;
          return acc;
        }, {})).sort((a, b) => a[0].localeCompare(b[0]));

        const uid = `ev-${plugin.plugin_id}`;
        const sample = plugin.validated_sample;
        let evidenceHtml = '';
        if (sample) {
          const terms = sample.highlight_terms || [];
          const rawOutput = sample.stdout || '(no output captured)';
          const relevant = sample.relevant_lines || [];

          // Primary display: relevant lines only (highlighted), or full output if short
          let primaryText, secondaryText;
          if (relevant.length > 0 && rawOutput.split('\\n').length > relevant.length + 3) {
            primaryText = relevant.join('\\n');
            secondaryText = rawOutput;
          } else {
            primaryText = rawOutput;
            secondaryText = null;
          }

          const highlightedPrimary = highlightEvidence(escapeHtml(primaryText), terms);
          const fullOutputHtml = secondaryText
            ? `<span class="full-output-toggle" onclick="toggleFullOutput('${uid}')">Show full output (${rawOutput.split('\\n').length} lines)</span>
               <div class="full-output-box" id="full-${uid}">${highlightEvidence(escapeHtml(secondaryText), terms)}</div>`
            : '';

          evidenceHtml = `
            <div class="evidence-label">Validated evidence &mdash; ${escapeHtml(String(sample.host))}:${escapeHtml(String(sample.port))}</div>
            <div class="evidence-toggle" id="toggle-${uid}" onclick="toggleEvidence('${uid}')">
              <span class="toggle-icon">+</span> Show command output
            </div>
            <div class="evidence-box" id="box-${uid}"><strong>Command:</strong> ${escapeHtml(sample.command || '')}

${highlightedPrimary}
${fullOutputHtml}</div>`;
        }

        const sectionHtml = `
          <section class="plugin">
            <h2>${plugin.plugin_id} - ${escapeHtml(plugin.plugin_name)}</h2>
            <p>${escapeHtml(plugin.plugin_summary)}</p>
            <ul class="chips">
              <li class="chip sev-${escapeHtml(String(plugin.plugin_severity))}">severity ${escapeHtml(String(plugin.plugin_severity))}</li>
              ${summary.map(([status, count]) => `<li class="chip">${escapeHtml(status)}: ${count}</li>`).join('')}
            </ul>
            ${evidenceHtml}
            <details style="margin-top:0.85rem">
              <summary>Show ${rows.length} result rows</summary>
              <table>
                <thead>
                  <tr>
                    <th>Host</th><th>Port</th><th>Status</th><th>Reason</th>
                    <th>Analyst Note</th><th>Source</th><th>Executed At</th><th>Command</th>
                  </tr>
                </thead>
                <tbody>
                  ${rows.slice(0, 200).map(row => `
                    <tr>
                      <td>${escapeHtml(String(row.host))}</td>
                      <td>${escapeHtml(String(row.port))}</td>
                      <td>${escapeHtml(row.status)}</td>
                      <td>${escapeHtml(row.reason)}</td>
                      <td>${escapeHtml(row.analyst_note)}</td>
                      <td>${escapeHtml(row.source)}</td>
                      <td>${escapeHtml(row.executed_at)}</td>
                      <td><code>${escapeHtml(row.command)}</code></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </details>
          </section>
        `;
        groupedSections[String(plugin.plugin_severity) || "-"].push(sectionHtml);
      });

      LAST_PLUGIN_COUNT = renderedPlugins;
      const severityOrder = [
        ["4", "Critical Severity"],
        ["3", "High Severity"],
        ["2", "Medium Severity"],
        ["1", "Low Severity"],
        ["-", "Unscored"],
      ];
      const sections = severityOrder
        .filter(([severity]) => groupedSections[severity].length)
        .map(([severity, title]) => `
          <div class="group-title">${title}</div>
          ${groupedSections[severity].join('')}
        `)
        .join('');

      stats.textContent = `${renderedPlugins} plugins, ${renderedRows} visible results`;
      container.innerHTML = sections || '<p>No results match the current filters.</p>';
    }

    function exportFilteredCsv() {
      const header = [
        "plugin_id",
        "plugin_name",
        "plugin_summary",
        "plugin_severity",
        "host",
        "port",
        "status",
        "reason",
        "analyst_note",
        "source",
        "executed_at",
        "command",
      ];
      const lines = [header.join(",")];
      for (const row of LAST_ROWS) {
        lines.push([
          row.plugin_id,
          row.plugin_name,
          row.plugin_summary,
          row.plugin_severity,
          row.host,
          row.port,
          row.status,
          row.reason,
          row.analyst_note,
          row.source,
          row.executed_at,
          row.command,
        ].map(csvEscape).join(","));
      }
      const blob = new Blob([lines.join("\\n") + "\\n"], {type: "text/csv;charset=utf-8"});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "nessus-filtered-results.csv";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }

    function toggleEvidence(uid) {
      const toggle = document.getElementById('toggle-' + uid);
      const box    = document.getElementById('box-' + uid);
      if (!toggle || !box) return;
      const opening = !box.classList.contains('visible');
      box.classList.toggle('visible', opening);
      toggle.querySelector('.toggle-icon').textContent = opening ? '−' : '+';
    }

    function toggleFullOutput(uid) {
      const el = document.getElementById('full-' + uid);
      if (!el) return;
      const opening = el.style.display !== 'block';
      el.style.display = opening ? 'block' : 'none';
      const tog = el.previousElementSibling;
      if (tog && tog.classList.contains('full-output-toggle')) {
        const lines = (el.textContent.match(/\\n/g) || []).length + 1;
        tog.textContent = opening ? 'Hide full output' : `Show full output (${lines} lines)`;
      }
    }

    // Highlight only the specific terms that justify the validated verdict for this finding.
    function highlightEvidence(text, terms) {
      if (!terms || !terms.length) return text;
      let result = text;
      for (const term of terms) {
        if (!term) continue;
        // Escape the term for use in a regex, then do a case-insensitive global replace.
        const escaped = term.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
        try {
          result = result.replace(
            new RegExp('(' + escaped + ')', 'gi'),
            '<span class="ev-highlight">$1</span>'
          );
        } catch (e) { /* skip malformed term */ }
      }
      return result;
    }

    function csvEscape(value) {
      const text = String(value ?? "");
      return `"${text.replaceAll('"', '""')}"`;
    }

    function escapeHtml(value) {
      return value
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;');
    }

    [pluginFilter, findingFilter, severityFilter, statusFilter, hostFilter, sourceFilter, tpOnly].forEach(node => {
      node.addEventListener('input', render);
      node.addEventListener('change', render);
    });
    exportCsv.addEventListener('click', exportFilteredCsv);
    render();
  </script>
"""
        + """
</body>
</html>
""").replace("REPORT_TITLE_PLACEHOLDER", report_title)
    )
    return output_path
