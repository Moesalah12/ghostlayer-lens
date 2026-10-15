'use strict';
const $ = id => document.getElementById(id);
function sessionKey() {
  const supplied = new URLSearchParams(location.hash.slice(1)).get('key');
  try {
    if (supplied) sessionStorage.setItem('lens-session-key', supplied);
    return supplied || sessionStorage.getItem('lens-session-key') || '';
  } catch { return supplied || ''; }
}
const key = sessionKey();
history.replaceState(null, '', location.pathname);
let selectedFile = null, currentReport = null, selectedNode = null, busy = false;
const bytes = value => value < 1024 ? `${value} B` : value < 1048576 ? `${(value/1024).toFixed(1)} KiB` : `${(value/1048576).toFixed(1)} MiB`;
function element(tag, text, className) { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (className) el.className = className; return el; }
function choose(file) {
  if (busy || !file) return;
  selectedFile = file;
  $('selected').hidden = false;
  $('selected').textContent = `${file.name} · ${bytes(file.size)}`;
  $('scan').disabled = file.size > 512*1024*1024 || !key;
  $('message').textContent = file.size > 512*1024*1024 ? 'This file exceeds the 512 MiB inspection limit. Choose a smaller file.' : '';
}
$('file').addEventListener('change', e => choose(e.target.files[0]));
for (const event of ['dragenter','dragover']) $('dropzone').addEventListener(event, e => { e.preventDefault(); $('dropzone').classList.add('drag'); });
for (const event of ['dragleave','drop']) $('dropzone').addEventListener(event, e => { e.preventDefault(); $('dropzone').classList.remove('drag'); });
$('dropzone').addEventListener('drop', e => { if (e.dataTransfer.files.length > 1) { $('message').textContent = 'Choose one file at a time. Put multiple files into a ZIP to inspect them together.'; return; } choose(e.dataTransfer.files[0]); });
document.addEventListener('dragover', e => e.preventDefault());
document.addEventListener('drop', e => e.preventDefault());
$('scan').addEventListener('click', () => selectedFile && inspect(selectedFile));
$('filter').addEventListener('change', renderEvidence);
$('all').addEventListener('click', () => { selectedNode = null; renderTree(); renderEvidence(); });
function setBusy(value) { busy=value; $('scan').disabled=value || !selectedFile || selectedFile.size>512*1024*1024 || !key; $('demo').disabled=value || !key; $('file').disabled=value; }
async function inspect(file) {
  if (busy) return;
  currentReport = null; selectedNode = null;
  $('report').hidden = true; $('empty').hidden = true; $('export').hidden = true; $('summary-export').hidden = true;
  $('message').textContent = 'Inspecting locally… Reading supported content without executing it.';
  setBusy(true);
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 150000);
  try {
    const response = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/octet-stream','X-Lens-Token':key,'X-Lens-Filename':encodeURIComponent(file.name)}, body:file, signal:controller.signal});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Inspection failed.');
    currentReport = result;
    $('message').textContent = '';
    renderReport();
  } catch(error) {
    $('message').textContent = error.name === 'AbortError' ? 'Inspection timed out. No completed assessment is available.' : `Inspection stopped: ${error.message}. The file has not been assessed.`;
    $('empty').hidden = false;
  } finally { clearTimeout(timer); setBusy(false); }
}
function renderReport() {
  const r=currentReport;
  $('report').hidden=false; $('export').hidden=false; $('summary-export').hidden=false;
  const concern=r.assessment==='review_recommended', gaps=r.coverage==='incomplete';
  $('assessment').className=`assessment${concern?'':' neutral'}`;
  $('assessment').replaceChildren(element('strong',concern?'Review recommended':gaps?'No rule matches · inspection incomplete':'No rule matches in supported checks'),element('p',gaps?'Some content could not be inspected. Review the coverage gaps below. This is not a safety verdict.':'Only the documented static checks were applied. No result guarantees that a file is safe.'));
  $('node-count').textContent=r.stats.nodes; $('finding-count').textContent=r.findings.filter(f=>f.severity!=='info').length;
  $('gap-count').textContent=r.nodes.filter(n=>n.status==='not_inspected').length;
  $('byte-count').textContent=bytes(r.stats.decompressed_bytes);
  $('report-foot').textContent=`Engine ${r.engine_version} · ${new Date(r.created_at).toLocaleString()} · SHA-256 ${r.nodes[0].sha256 || 'unavailable'}. ${r.notice}${r.limits_hit.length?' Limits reached: '+r.limits_hit.join(', ')+'.':''}`;
  renderTree(); renderEvidence();
}
function renderTree() {
  const tree=$('tree'); tree.replaceChildren();
  const byId=new Map(currentReport.nodes.map(n=>[n.id,n]));
  for (const node of currentReport.nodes) {
    let depth=0, parent=node.parent_id;
    while(parent && depth<5) {depth++; parent=byId.get(parent)?.parent_id;}
    const button=element('button',undefined,`node${selectedNode===node.id?' active':''}`);
    button.setAttribute('aria-pressed',String(selectedNode===node.id));
    const label=element('span',`${'↳ '.repeat(depth)}${node.name}`);
    button.append(label,element('small',`${node.kind} · ${bytes(node.size_bytes)} · ${node.status.replaceAll('_',' ')}`));
    button.addEventListener('click',()=>{selectedNode=node.id;renderTree();renderEvidence();}); tree.append(button);
  }
}
function renderEvidence() {
  if (!currentReport) return;
  const filter=$('filter').value, byId=new Map(currentReport.nodes.map(n=>[n.id,n]));
  const findings=currentReport.findings.filter(f=>(!selectedNode || f.node_id===selectedNode) && (filter==='all' || filter===f.severity));
  const container=$('evidence'); container.replaceChildren();
  for(const finding of findings) {
    const card=element('article',undefined,`finding ${finding.severity}`);
    card.append(element('span',`${finding.severity.toUpperCase()} · ${finding.id}`,'severity'),element('h3',finding.title),element('div',`${byId.get(finding.node_id)?.name || finding.node_id}${finding.line?' · line '+finding.line:''}`,'source'),element('p',finding.detail));
    if(finding.evidence) card.append(element('pre',finding.evidence));
    container.append(card);
  }
  if(!findings.length) container.append(element('p','No findings for this selection. This does not establish that the content is safe.','empty-findings'));
  const refs=$('references'); refs.replaceChildren();
  const nodes=currentReport.nodes.filter(n=>!selectedNode || n.id===selectedNode);
  const references=nodes.flatMap(n=>n.references.map(ref=>({...ref,node:n.name})));
  if(references.length) {
    refs.append(element('strong','Referenced addresses — displayed as text, never contacted'));
    for(const ref of references) refs.append(element('code',`${ref.value} · ${ref.node} (${ref.source})`));
  }
}
function download(value,name) {const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'})); const link=element('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('export').addEventListener('click',()=>{if(currentReport && confirm('The full report includes filenames, hashes, script excerpts, and referenced addresses. Review it before sharing. Export to this computer?')) download(currentReport,'ghostlayer-lens-report.json');});
$('summary-export').addEventListener('click',()=>{if(currentReport) download({schema_version:1,engine_version:currentReport.engine_version,assessment:currentReport.assessment,coverage:currentReport.coverage,stats:currentReport.stats,limits_hit:currentReport.limits_hit,rule_counts:currentReport.findings.reduce((out,f)=>{out[f.rule]=(out[f.rule]||0)+1;return out;},{}),notice:'Summary omits filenames, hashes, excerpts, and referenced addresses. No safety certification.'},'ghostlayer-lens-summary.json');});
// Construct a real, stored ZIP with CRC32 and central directory, entirely in memory.
// Demo data is explicit training material, not a recorded report or executable malware.
function crc32(data) {let crc=0xffffffff;for(const b of data){crc^=b;for(let i=0;i<8;i++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}return (crc^0xffffffff)>>>0;}
function trainingZip() {
  const encoder=new TextEncoder();
  const entries=[['README.txt','SYNTHETIC TRAINING DATA. Nothing here should be executed. Lens detects lexical indicators, including comments.\n'],['setup.ps1.txt','# TRAINING ONLY: these comments illustrate review signals.\n# Example: Invoke-WebRequest https://downloads.example.invalid/package.txt\n# Example: Start-Process viewer.exe -Verb RunAs\nWrite-Output "Training fixture"\n'],['photo.jpg.exe','MZ — fictional marker fixture; not a valid Windows executable.'],['nested/notes.txt','Ordinary notes with no matching review signals.\n']];
  let offset=0, count=0;const parts=[],central=[];
  for(const [name,text] of entries){const n=encoder.encode(name),d=encoder.encode(text),crc=crc32(d);const local=new Uint8Array(30+n.length),lv=new DataView(local.buffer);lv.setUint32(0,0x04034b50,true);lv.setUint16(4,20,true);lv.setUint32(14,crc,true);lv.setUint32(18,d.length,true);lv.setUint32(22,d.length,true);lv.setUint16(26,n.length,true);local.set(n,30);parts.push(local,d);const c=new Uint8Array(46+n.length),cv=new DataView(c.buffer);cv.setUint32(0,0x02014b50,true);cv.setUint16(4,20,true);cv.setUint16(6,20,true);cv.setUint32(16,crc,true);cv.setUint32(20,d.length,true);cv.setUint32(24,d.length,true);cv.setUint16(28,n.length,true);cv.setUint32(42,offset,true);c.set(n,46);central.push(c);offset+=local.length+d.length;count++;}
  const length=central.reduce((n,c)=>n+c.length,0),end=new Uint8Array(22),view=new DataView(end.buffer);view.setUint32(0,0x06054b50,true);view.setUint16(8,count,true);view.setUint16(10,count,true);view.setUint32(12,length,true);view.setUint32(16,offset,true);return new File([...parts,...central,end],'ghostlayer-training.zip',{type:'application/zip'});
}
$('demo').addEventListener('click',()=>{const file=trainingZip();choose(file);inspect(file);});
if(!key){$('message').textContent='Local session key missing. Open the full startup URL printed by python -m lens serve. The key stays on this computer.';$('demo').disabled=true;}
