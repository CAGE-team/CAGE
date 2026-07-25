const BASE = 'http://localhost:5000';

// Alert/event fields (RBAC subject names, exec'd binary paths, etc.) can
// contain attacker-controlled text that Kubernetes itself never validates
// as safe HTML. Every value interpolated into innerHTML below must go
// through this first.
function esc(s){
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
setInterval(() => { document.getElementById('clock').textContent = new Date().toTimeString().slice(0,8); }, 1000);

let gNodes=[], gEdges=[], alerts=[], evtCount=0, evtMinBucket=0, animPaused=false, selPod=null;
let nodePositions={}, dragging=null, dragOff={x:0,y:0}, animFrame;
let chainHistory=[], expandedPod=null, health=null, currentPage='live';
const podColorMap={};
const POD_PALETTE=['#38bdf8','#f472b6','#a3e635','#fb923c','#c084fc','#2dd4bf','#facc15','#818cf8'];
let podColorIdx=0;
function podColor(key){
  if(!podColorMap[key]){podColorMap[key]=POD_PALETTE[podColorIdx%POD_PALETTE.length];podColorIdx++;}
  return podColorMap[key];
}

const MITRE_DESC={
  'T1059':'Execution: a shell process spawned inside a container',
  'T1021':'Remote exec: someone ran kubectl exec into this pod',
  'T1552':'Credential Access: a Kubernetes secret was read via the API',
  'T1610':'Network Flow: this pod opened a TCP connection to another pod',
  'T1611':'Escape to Host: container-escape tooling or host-runtime paths were used inside the container',
  'T1548':'Privilege Escalation: sudo/su/setcap used inside the container',
  'T1548-PRIV-POD':'Privilege Escalation: a pod was deployed with privileged/host-namespace settings',
  'T1548.005':'RBAC Abuse: a Role/ClusterRoleBinding grants excessive Kubernetes permissions',
  'T1496':'Resource Hijacking: cryptomining process signature detected',
  'T1499':'Endpoint DoS: fork-bomb-like burst of process executions',
  'T1613':'Discovery: a burst of RBAC object reads (role/binding enumeration)',
};
const STEP_COLOR={
  T1021:'#a855f7', T1059:'#eab308', T1552:'#ef4444', T1610:'#06b6d4',
  T1611:'#ef4444', T1548:'#f97316', 'T1548-PRIV-POD':'#f97316',
  'T1548.005':'#ec4899', T1496:'#eab308', T1499:'#eab308', T1613:'#3b82f6',
};
const ALL_TECHNIQUES=['T1021','T1059','T1610','T1552','T1611','T1548','T1548-PRIV-POD','T1548.005','T1496','T1499','T1613'];

// A chain's `rule` field mixes unicode arrows ("T1059→T1552") and ASCII
// arrows ("T1059->T1548->T1611") depending on which check fired it — split
// on both so every chain (not just the ASCII-arrow ones) is recognized.
function splitChainSteps(rule){ return (rule||'').split(/→|->/).filter(Boolean); }
function isChainRule(rule){ return splitChainSteps(rule).length>1; }
function chainKey(rule){ return splitChainSteps(rule).join('>'); }
function stepBadge(step){
  const c=STEP_COLOR[step]||'#94a3b8';
  return `<span class="chain-step" style="background:${c}22;color:${c};border:1px solid ${c}55" title="${esc(MITRE_DESC[step]||'')}">${esc(step)}</span>`;
}
function ruleTitle(rule){
  if(!rule) return '';
  const steps=splitChainSteps(rule);
  if(steps.length>1) return steps.map(r=>`${r}: ${MITRE_DESC[r]||'chained technique'}`).join('\n');
  return MITRE_DESC[rule]||'';
}

// ── Attack graph layout ──
// Only nodes whose ROLE is structurally guaranteed to exist in any CAGE
// deployment (the virtual admin/host nodes, the attacker pod by convention,
// kube-apiserver/tetragon by name prefix) get a fixed anchor position.
// Everything else falls through to a deterministic namespace-clustered
// layout below, instead of a hand-maintained pod-name-suffix lookup table
// that only matches one specific cluster's pod hashes.
const FIXED_LAYOUT = {
  'admin':        {xp:0.10, yp:0.50},
  'attacker':     {xp:0.42, yp:0.50},
  'kube-api':     {xp:0.80, yp:0.50},
  'tetragon':     {xp:0.42, yp:0.15},
  'host':         {xp:0.42, yp:0.85},
  'legit-app':    {xp:0.20, yp:0.82},
};
function getFixedKey(node){
  if(node.uid==='admin') return 'admin';
  if(node.uid==='host') return 'host';
  if(node.name==='attacker') return 'attacker';
  if(node.name&&node.name.startsWith('kube-apiserver-')) return 'kube-api';
  if(node.name&&node.name.startsWith('tetragon-')&&!node.name.startsWith('tetragon-operator')) return 'tetragon';
  if(node.name==='legitimate-app') return 'legit-app';
  return null;
}
function strHash(s){ let h=0; s=String(s||''); for(let i=0;i<s.length;i++){h=(h*31+s.charCodeAt(i))|0;} return Math.abs(h); }
function namespaceLayout(node,W,H){
  const angle=(strHash(node.namespace)%360)*Math.PI/180 + ((strHash(node.uid)%100)/100-0.5)*0.6;
  const r=Math.min(W,H)*0.38*(0.7+(strHash(node.name)%100)/100*0.25);
  return {x:W/2+Math.cos(angle)*r, y:H/2+Math.sin(angle)*r};
}

const canvas = document.getElementById('graph-canvas');
const ctx = canvas.getContext('2d');

const MIN_GRAPH_W=1200, MIN_GRAPH_H=800;
function resize(){
  const wrap=document.getElementById('graph-scroll');
  const w=Math.max(wrap.clientWidth||0, MIN_GRAPH_W);
  const h=Math.max(wrap.clientHeight||0, MIN_GRAPH_H);
  canvas.width=w; canvas.height=h;
  canvas.style.width=w+'px'; canvas.style.height=h+'px';
}
window.addEventListener('resize',()=>{resize();applyFixedLayout();});

let graphZoom=1;
const ZOOM_MIN=0.4, ZOOM_MAX=2.5;
function applyZoom(){
  canvas.style.transformOrigin='0 0';
  canvas.style.transform=`scale(${graphZoom})`;
  const zl=document.getElementById('zoom-label'); if(zl) zl.textContent=Math.round(graphZoom*100)+'%';
}
function zoomBy(delta){ setZoom(graphZoom+delta); }
function resetZoom(){ setZoom(1); }
function setZoom(z){ graphZoom=Math.min(ZOOM_MAX,Math.max(ZOOM_MIN,z)); applyZoom(); }
document.getElementById('graph-scroll').addEventListener('wheel',e=>{
  e.preventDefault();
  const wrap=document.getElementById('graph-scroll');
  const r=wrap.getBoundingClientRect();
  const beforeX=(e.clientX-r.left+wrap.scrollLeft)/graphZoom;
  const beforeY=(e.clientY-r.top+wrap.scrollTop)/graphZoom;
  setZoom(graphZoom + (e.deltaY<0?0.1:-0.1));
  wrap.scrollLeft=beforeX*graphZoom-(e.clientX-r.left);
  wrap.scrollTop=beforeY*graphZoom-(e.clientY-r.top);
},{passive:false});
applyZoom();

function applyFixedLayout(){
  const W=canvas.width, H=canvas.height;
  gNodes.forEach(n=>{
    const key=getFixedKey(n);
    if(key && FIXED_LAYOUT[key]){
      nodePositions[n.uid]={x:W*FIXED_LAYOUT[key].xp, y:H*FIXED_LAYOUT[key].yp};
    } else if(!nodePositions[n.uid]){
      nodePositions[n.uid]=namespaceLayout(n,W,H);
    }
  });
}
function initGraph(nodes,edges){ gNodes=nodes; gEdges=edges; applyFixedLayout(); if(!animFrame) animLoop(0); }
function updateGraphData(nodes,edges){ gNodes=nodes; gEdges=edges; applyFixedLayout(); populateKcPodSelect(); }

let packetT=0;
function animLoop(ts){
  if(!animPaused) packetT=ts;
  ctx.clearRect(0,0,canvas.width,canvas.height);
  ctx.save();ctx.strokeStyle='rgba(255,255,255,.025)';ctx.lineWidth=.5;
  for(let x=0;x<canvas.width;x+=40){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,canvas.height);ctx.stroke();}
  for(let y=0;y<canvas.height;y+=40){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(canvas.width,y);ctx.stroke();}
  ctx.restore();
  const selfLoopCounts={}, selfLoopIndex=new Map();
  gEdges.forEach(e=>{ if(e.from===e.to){ const i=selfLoopCounts[e.from]||0; selfLoopIndex.set(e,i); selfLoopCounts[e.from]=i+1; } });
  gEdges.forEach(e=>drawEdge(e,packetT,selfLoopIndex.get(e)||0,selfLoopCounts[e.from]||1));
  gNodes.forEach(n=>drawNode(n));
  animFrame=requestAnimationFrame(animLoop);
}

function nodeRadius(n){
  if(n.uid==='admin') return 18;
  if(n.uid==='host') return 20;
  if(n.uid&&n.uid.startsWith('rbac:')) return 16;
  if(n.name==='attacker') return 26;
  if(n.name&&n.name.startsWith('kube-apiserver')) return 22;
  if(n.name&&n.name.startsWith('tetragon')) return 18;
  if(n.namespace==='default') return 16;
  return 10;
}
function nodeColor(n){
  if(n.severity==='critical') return '#ef4444';
  if(n.severity==='high') return '#f59e0b';
  if(n.severity==='medium') return '#eab308';
  if(n.uid==='admin') return '#a855f7';
  if(n.uid==='host') return '#ef4444';
  if(n.uid&&n.uid.startsWith('rbac:')) return '#ec4899';
  if(n.name&&n.name.startsWith('tetragon')) return '#14b8a6';
  if(n.namespace!=='default') return '#475569';
  return '#22c55e';
}

function drawEdge(e,t,loopIdx,loopTotal){
  const fp=nodePositions[e.from], tp=nodePositions[e.to];
  if(!fp||!tp) return;
  const fn=gNodes.find(n=>n.uid===e.from), tn=gNodes.find(n=>n.uid===e.to);
  if(!fn||!tn) return;

  if(e.from===e.to){
    const r=nodeRadius(fn);
    const n=loopTotal||1, i=loopIdx||0;
    const spread=Math.PI/2.2;
    const baseAngle=-Math.PI/2 - (spread*(n-1))/2 + spread*i;
    const dist=r+32;
    const cx=fp.x+Math.cos(baseAngle)*dist*0.35;
    const cy=fp.y+Math.sin(baseAngle)*dist;
    ctx.save();
    ctx.shadowColor=e.color||'#3b82f6'; ctx.shadowBlur=6;
    ctx.strokeStyle=e.color||'#3b82f6'; ctx.lineWidth=2.5; ctx.globalAlpha=.85;
    ctx.setLineDash([8,4]); ctx.lineDashOffset=-(t*0.04);
    ctx.beginPath();
    ctx.arc(cx,cy,20,0.15*Math.PI,0.85*Math.PI,false);
    ctx.stroke();
    ctx.setLineDash([]); ctx.shadowBlur=0;
    const ax=fp.x-r*0.3, ay=fp.y-r-2;
    ctx.globalAlpha=1; ctx.fillStyle=e.color||'#3b82f6';
    ctx.beginPath(); ctx.moveTo(ax,ay); ctx.lineTo(ax-8,ay-10); ctx.lineTo(ax+8,ay-10); ctx.closePath(); ctx.fill();
    const label=e.type||'';
    ctx.font='bold 11px SF Mono,monospace'; ctx.textAlign='center';
    const tw=ctx.measureText(label).width;
    ctx.globalAlpha=.9; ctx.fillStyle='rgba(10,14,26,.85)';
    ctx.fillRect(cx-tw/2-5,cy-30,tw+10,16);
    ctx.strokeStyle=e.color||'#3b82f6'; ctx.lineWidth=1;
    ctx.strokeRect(cx-tw/2-5,cy-30,tw+10,16);
    ctx.fillStyle=e.color||'#3b82f6'; ctx.globalAlpha=1;
    ctx.fillText(label,cx,cy-18);
    ctx.restore();
    return;
  }

  const dx=tp.x-fp.x,dy=tp.y-fp.y,dist=Math.sqrt(dx*dx+dy*dy);
  if(dist<1) return;
  const ux=dx/dist,uy=dy/dist;
  const r1=nodeRadius(fn)+3,r2=nodeRadius(tn)+5;
  const sx=fp.x+ux*r1,sy=fp.y+uy*r1;
  const ex=tp.x-ux*r2,ey=tp.y-uy*r2;

  ctx.save();
  ctx.shadowColor=e.color||'#3b82f6'; ctx.shadowBlur=6;
  ctx.strokeStyle=e.color||'#3b82f6'; ctx.lineWidth=2.5; ctx.globalAlpha=.85;
  ctx.setLineDash([8,4]); ctx.lineDashOffset=-(t*0.04);
  ctx.beginPath();ctx.moveTo(sx,sy);ctx.lineTo(ex,ey);ctx.stroke();
  ctx.setLineDash([]); ctx.shadowBlur=0;

  const angle=Math.atan2(ey-sy,ex-sx);
  ctx.globalAlpha=1; ctx.fillStyle=e.color||'#3b82f6';
  ctx.beginPath(); ctx.moveTo(ex,ey);
  ctx.lineTo(ex-12*Math.cos(angle-.4),ey-12*Math.sin(angle-.4));
  ctx.lineTo(ex-12*Math.cos(angle+.4),ey-12*Math.sin(angle+.4));
  ctx.closePath();ctx.fill();

  const mx=(sx+ex)/2,my=(sy+ey)/2;
  const nx=-uy,ny=ux;
  const lx=mx+nx*16,ly=my+ny*16;
  const label=e.type||'';
  ctx.font='bold 11px SF Mono,monospace'; ctx.textAlign='center';
  const tw=ctx.measureText(label).width;
  ctx.globalAlpha=.9; ctx.fillStyle='rgba(10,14,26,.85)';
  ctx.fillRect(lx-tw/2-5,ly-8,tw+10,16);
  ctx.strokeStyle=e.color||'#3b82f6'; ctx.lineWidth=1;
  ctx.strokeRect(lx-tw/2-5,ly-8,tw+10,16);
  ctx.fillStyle=e.color||'#3b82f6'; ctx.globalAlpha=1;
  ctx.fillText(label,lx,ly+3);

  const progress=((t*0.0005)%1);
  const px=fp.x+(tp.x-fp.x)*progress, py=fp.y+(tp.y-fp.y)*progress;
  ctx.globalAlpha=.95; ctx.shadowColor=e.color||'#3b82f6'; ctx.shadowBlur=8;
  ctx.fillStyle=e.color||'#3b82f6';
  ctx.beginPath();ctx.arc(px,py,4,0,Math.PI*2);ctx.fill();
  ctx.shadowBlur=0;
  ctx.restore();
}

function drawNode(n){
  const pos=nodePositions[n.uid];
  if(!pos) return;
  const {x,y}=pos;
  const r=nodeRadius(n);
  const color=nodeColor(n);
  const isSel=selPod===n.uid;
  ctx.save();

  if(n.severity==='critical'){
    const glow=ctx.createRadialGradient(x,y,r,x,y,r+24);
    glow.addColorStop(0,'rgba(239,68,68,.25)'); glow.addColorStop(1,'rgba(239,68,68,0)');
    ctx.beginPath();ctx.arc(x,y,r+24,0,Math.PI*2); ctx.fillStyle=glow;ctx.fill();
  }

  if(n.uid==='admin'){
    ctx.globalAlpha=1; ctx.fillStyle=color+'20'; ctx.strokeStyle=color;ctx.lineWidth=2;
    ctx.beginPath(); ctx.moveTo(x,y-r);ctx.lineTo(x+r,y);ctx.lineTo(x,y+r);ctx.lineTo(x-r,y);
    ctx.closePath();ctx.fill();ctx.stroke();
    ctx.fillStyle=color; ctx.beginPath();ctx.arc(x,y,r*.3,0,Math.PI*2);ctx.fill();
  } else {
    if(isSel){
      ctx.beginPath();ctx.arc(x,y,r+6,0,Math.PI*2);
      ctx.strokeStyle='#fff';ctx.lineWidth=1;ctx.globalAlpha=.25;ctx.stroke();
    }
    ctx.globalAlpha=1;
    ctx.beginPath();ctx.arc(x,y,r,0,Math.PI*2);
    ctx.fillStyle=color+'22';ctx.fill();
    ctx.strokeStyle=color;ctx.lineWidth=2;ctx.stroke();
    ctx.beginPath();ctx.arc(x,y,r*.38,0,Math.PI*2);
    ctx.fillStyle=color;ctx.fill();
  }

  const label=n.name.length>16?n.name.slice(0,15)+'…':n.name;
  ctx.fillStyle='#e2e8f0';ctx.font='500 11px SF Mono,monospace';
  ctx.textAlign='center';ctx.globalAlpha=1;
  ctx.fillText(label,x,y+r+14);
  ctx.fillStyle='#64748b';ctx.font='9px SF Mono,monospace';
  const ns=n.namespace==='external'?'[external]':n.namespace;
  ctx.fillText(ns,x,y+r+25);

  if(n.alert_count>0){
    ctx.fillStyle=color;ctx.font='bold 9px monospace';
    ctx.fillText(`${n.alert_count} alerts`,x,y+r+35);
  }
  ctx.restore();
}

canvas.addEventListener('mousedown',e=>{
  const {mx,my}=cm(e);
  gNodes.forEach(n=>{
    const pos=nodePositions[n.uid];if(!pos)return;
    const dx=mx-pos.x,dy=my-pos.y;
    if(Math.sqrt(dx*dx+dy*dy)<nodeRadius(n)+6){dragging=n.uid;dragOff={x:dx,y:dy};}
  });
});
canvas.addEventListener('mousemove',e=>{
  const {mx,my}=cm(e);
  if(dragging){nodePositions[dragging]={x:mx-dragOff.x,y:my-dragOff.y};}
  let hit=null;
  gNodes.forEach(n=>{
    const pos=nodePositions[n.uid];if(!pos)return;
    const dx=mx-pos.x,dy=my-pos.y;
    if(Math.sqrt(dx*dx+dy*dy)<nodeRadius(n)+6) hit=n;
  });
  const tt=document.getElementById('tt');
  if(hit){
    tt.className='show';tt.style.left=(e.clientX+14)+'px';tt.style.top=(e.clientY-10)+'px';
    document.getElementById('tt-name').textContent=hit.name;
    document.getElementById('tt-ns').textContent=hit.namespace;
    document.getElementById('tt-uid').textContent=(hit.uid||'').slice(0,20)+'…';
    document.getElementById('tt-ip').textContent=hit.ip||'—';
    document.getElementById('tt-alerts').textContent=hit.alert_count||'0';
  } else {tt.className='';}
});
canvas.addEventListener('mouseup',()=>{dragging=null;});
canvas.addEventListener('click',e=>{
  const {mx,my}=cm(e);
  gNodes.forEach(n=>{
    const pos=nodePositions[n.uid];if(!pos)return;
    const dx=mx-pos.x,dy=my-pos.y;
    if(Math.sqrt(dx*dx+dy*dy)<nodeRadius(n)+6) selPod=n.uid;
  });
});
function cm(e){const r=canvas.getBoundingClientRect();return{mx:(e.clientX-r.left)*(canvas.width/r.width),my:(e.clientY-r.top)*(canvas.height/r.height)};}
function resetLayout(){nodePositions={};applyFixedLayout();}
function togglePause(){animPaused=!animPaused;document.getElementById('pause-btn').textContent=animPaused?'▶ Resume':'⏸ Pause';}

// ── Graph reparenting between Overview's compact slot and the full Graph page ──
function moveGraphToPage(target){
  const block=document.getElementById('graph-block');
  const dest=document.getElementById(target==='graph'?'graph-slot-full':'graph-slot-live');
  if(dest && block.parentElement!==dest) dest.appendChild(block);
  resize(); applyFixedLayout();
}

// ── Data fetching ──
async function fetchAll(){
  try{
    const [pR,aR,sR,gR]=await Promise.all([
      fetch(BASE+'/api/pods'),fetch(BASE+'/api/alerts'),
      fetch(BASE+'/api/stats'),fetch(BASE+'/api/graph'),
    ]);
    alerts=await aR.json();
    const stats=await sR.json();
    const graph=await gR.json();
    updateMetrics(stats);
    renderPodList(graph.nodes);
    initGraph(graph.nodes,graph.edges);
    moveGraphToPage(currentPage==='graph'?'graph':'live');
    populateKcPodSelect();
    renderAlerts(sortedAlertsView());
    chainHistory=alerts.filter(a=>a.severity==='CRITICAL'&&isChainRule(a.rule))
      .slice().reverse().slice(0,25)
      .map(a=>({rule:a.rule,pod:`${a.namespace}/${a.pod_name}`,
        ts:a.timestamp?new Date(a.timestamp).toTimeString().slice(0,8):'—',desc:a.description||''}));
    renderChainHistory();
    drawSpark();
    document.getElementById('conn-status').textContent='LIVE';
    document.getElementById('conn-status').className='live';
    refreshCurrentPage();
  }catch(e){
    document.getElementById('conn-status').textContent='disconnected';
    document.getElementById('conn-status').className='dead';
    setTimeout(fetchAll,3000);
  }
}

function connectAlertStream(){
  const es=new EventSource(BASE+'/stream/alerts');
  es.onmessage=e=>{
    const msg=JSON.parse(e.data);if(msg.type!=='alert')return;
    const alert=msg.data;alerts.unshift(alert);prependAlert(alert);
    if(alert.severity==='CRITICAL'&&isChainRule(alert.rule)){
      renderChainBanner(alert);
      document.getElementById('chain-banner').classList.add('show');
      document.getElementById('chain-pod').textContent=`${alert.namespace}/${alert.pod_name}`;
      document.getElementById('chain-ts').textContent=new Date().toTimeString().slice(0,8);
      chainHistory.unshift({rule:alert.rule,pod:`${alert.namespace}/${alert.pod_name}`,
        ts:alert.timestamp?new Date(alert.timestamp).toTimeString().slice(0,8):new Date().toTimeString().slice(0,8),
        desc:alert.description||''});
      if(chainHistory.length>25) chainHistory.pop();
      renderChainHistory();
    }
    if(alert.severity==='CRITICAL') showToast(alert);
    sparkAdd(alert.severity);
    fetchStats();fetchGraph();fetchHealth();
    renderKillChain(document.getElementById('kc-pod-select').value||'attacker');
    refreshCurrentPage();
    document.getElementById('conn-status').textContent='LIVE';
    document.getElementById('conn-status').className='live';
  };
  es.onerror=()=>{setTimeout(connectAlertStream,3000);es.close();};
}

function connectEventStream(){
  const es=new EventSource(BASE+'/stream/events');
  es.onmessage=e=>{
    const msg=JSON.parse(e.data);if(msg.type!=='event')return;
    evtCount++;evtMinBucket++;
    document.getElementById('evt-count').textContent=evtCount+' events';
    prependEvent(msg.data);
  };
  es.onerror=()=>{setTimeout(connectEventStream,3000);es.close();};
}

async function fetchHealth(){
  try{
    const r=await fetch(BASE+'/api/health');
    health=await r.json();
    updateHeaderDots();
    if(currentPage==='health') renderHealthPage();
  }catch(e){}
}

function updateHeaderDots(){
  if(!health) return;
  const setDot=(id,s)=>{
    const el=document.getElementById(id);
    if(!el||!s) return;
    el.className='dot '+(!s.enabled?'gray':(s.stale?'red':'green'));
    el.title = !s.enabled?'Disabled in current ABLATION_MODE'
      : s.stale?`No event in ${Math.round(s.age_seconds||0)}s — may be dead`
      : s.age_seconds!=null?`Last event ${Math.round(s.age_seconds)}s ago`:'No events seen yet';
  };
  setDot('dot-tetragon',health.sources.tetragon);
  setDot('dot-audit',health.sources.audit);
}

function updateMetrics(stats){
  document.getElementById('m-crit').textContent=stats.by_severity?.CRITICAL||0;
  document.getElementById('m-high').textContent=stats.by_severity?.HIGH||0;
  document.getElementById('m-med').textContent=stats.by_severity?.MEDIUM||0;
  document.getElementById('m-pods').textContent=stats.pods_tracked||0;
  document.getElementById('pod-count').textContent=(stats.pods_tracked||0)+' pods';
  const fired=ALL_TECHNIQUES.filter(t=>(stats.by_rule||{})[t]>0).length;
  document.getElementById('m-cov').textContent=`${fired}/${ALL_TECHNIQUES.length}`;
  document.getElementById('m-cov-fill').style.width=(fired/ALL_TECHNIQUES.length*100)+'%';
}

async function fetchStats(){
  try{const r=await fetch(BASE+'/api/stats');updateMetrics(await r.json());
  document.getElementById('alert-count').textContent=alerts.length+' alerts';}catch(e){}
}
async function fetchGraph(){
  try{const r=await fetch(BASE+'/api/graph');const g=await r.json();
  updateGraphData(g.nodes,g.edges);renderPodList(g.nodes);}catch(e){}
}

const SEV_COLORS={critical:'#ef4444',high:'#f59e0b',medium:'#eab308',clean:'#22c55e'};
function podInitials(name){return (name||'').replace(/-[a-z0-9]{5,}$/,'').slice(0,2).toUpperCase();}

// ── Dynamic chain banner (was hardcoded to one specific 3-step chain) ──
function renderChainBanner(alert){
  const steps=splitChainSteps(alert.rule);
  document.getElementById('chain-banner-steps').innerHTML=steps.map((s,i)=>
    stepBadge(s)+(i<steps.length-1?'<span class="chain-arrow">→</span>':'')
  ).join('');
}

function renderChainHistory(){
  const el=document.getElementById('chain-hist');
  document.getElementById('chain-count').textContent=chainHistory.length+' chains';
  if(chainHistory.length===0){el.innerHTML='<div class="chain-hist-empty">No attack chains detected yet</div>';return;}
  el.innerHTML='';
  chainHistory.forEach(c=>{
    const steps=splitChainSteps(c.rule);
    const dotColor=podColor(c.pod);
    const div=document.createElement('div');div.className='ch-item';
    div.innerHTML=`
      <div class="ch-steps">${steps.map((s,i)=>stepBadge(s)+(i<steps.length-1?'<span class="ch-arrow">→</span>':'')).join('')}</div>
      <div class="ch-meta"><span class="ch-pod"><span class="pod-dot" style="background:${dotColor}"></span>${esc(c.pod)}</span><span>${esc(c.ts)}</span></div>`;
    el.appendChild(div);
  });
}

// ── Sparkline: rolling 5-minute window (10s buckets), or full-session ──
const SPARK_BUCKET_MS=10000, SPARK_BUCKETS=30;
let sparkData=Array.from({length:SPARK_BUCKETS},()=>({CRITICAL:0,HIGH:0,MEDIUM:0}));
let sparkMode='5m';
function setSparkMode(m){
  sparkMode=m;
  document.getElementById('spark-5m-btn').classList.toggle('active',m==='5m');
  document.getElementById('spark-session-btn').classList.toggle('active',m==='session');
  drawSpark();
}
function sparkAdd(sev){
  if(!sparkData[SPARK_BUCKETS-1][sev]&&sparkData[SPARK_BUCKETS-1][sev]!==0) return;
  sparkData[SPARK_BUCKETS-1][sev]=(sparkData[SPARK_BUCKETS-1][sev]||0)+1;
  drawSpark();
}
function sparkTick(){ sparkData.shift(); sparkData.push({CRITICAL:0,HIGH:0,MEDIUM:0}); if(sparkMode==='5m') drawSpark(); }
function computeSessionBuckets(n=40){
  const buckets=Array.from({length:n},()=>({CRITICAL:0,HIGH:0,MEDIUM:0}));
  if(!alerts.length) return buckets;
  const times=alerts.map(a=>new Date(a.timestamp||Date.now()).getTime()).filter(t=>!isNaN(t));
  if(!times.length) return buckets;
  const min=Math.min(...times), max=Math.max(...times), span=Math.max(1,max-min);
  alerts.forEach(a=>{
    const t=new Date(a.timestamp||Date.now()).getTime();
    let idx=Math.floor(((t-min)/span)*n); if(idx>=n) idx=n-1; if(idx<0) idx=0;
    if(buckets[idx][a.severity]!==undefined) buckets[idx][a.severity]++;
  });
  return buckets;
}
const sparkCanvas=document.getElementById('spark-canvas');
const sparkCtx=sparkCanvas.getContext('2d');
function drawSpark(){
  const data = sparkMode==='session' ? computeSessionBuckets() : sparkData;
  const W=sparkCanvas.offsetWidth,H=34;
  sparkCanvas.width=W;sparkCanvas.height=H;
  sparkCtx.clearRect(0,0,W,H);
  const barW=W/data.length;
  const maxTotal=Math.max(1,...data.map(b=>b.CRITICAL+b.HIGH+b.MEDIUM));
  data.forEach((b,i)=>{
    const x=i*barW+1; let y=H;
    [['CRITICAL','#ef4444'],['HIGH','#f59e0b'],['MEDIUM','#eab308']].forEach(([key,color])=>{
      const v=b[key]||0; if(v===0) return;
      const h=(v/maxTotal)*(H-2);
      sparkCtx.fillStyle=color; sparkCtx.globalAlpha=.85;
      sparkCtx.fillRect(x,y-h,barW-2,h); y-=h;
    });
  });
}
setInterval(sparkTick,SPARK_BUCKET_MS);
window.addEventListener('resize',drawSpark);
drawSpark();

function podStats(node){
  const match=alerts.filter(a=>a.namespace===node.namespace&&a.pod_name===node.name);
  const sorted=match.slice().sort((a,b)=>new Date(a.timestamp||0)-new Date(b.timestamp||0));
  const first=sorted[0], last=sorted[sorted.length-1];
  const techSet=new Set(sorted.map(a=>a.rule).filter(Boolean));
  return {count:sorted.length, first, last, techs:[...techSet]};
}

function renderPodList(nodes){
  const list=document.getElementById('pod-list');
  const sorted=[...nodes].sort((a,b)=>{
    const s={critical:0,high:1,medium:2,clean:3};
    return (s[a.severity]||3)-(s[b.severity]||3);
  });
  list.innerHTML='';
  sorted.forEach(node=>{
    if(node.uid==='admin') return;
    const color=SEV_COLORS[node.severity]||'#64748b';
    if(node.alert_count>0) podColor(node.namespace+'/'+node.name);
    const div=document.createElement('div');
    div.className=`pod-item sev-${node.severity}${expandedPod===node.uid?' expanded':''}`;
    div.onclick=()=>{
      selPod=node.uid;
      expandedPod=(expandedPod===node.uid)?null:node.uid;
      renderPodList(gNodes);
    };
    const badgesHtml=node.alert_count>0
      ?`<div class="badge ${node.severity==='critical'?'crit':node.severity==='high'?'high':'med'}">${node.severity.toUpperCase()}</div>`
      :`<div class="badge ok">CLEAN</div>`;
    div.innerHTML=`
      <div class="pi-icon" style="background:${color}22;color:${color}">${esc(podInitials(node.name))}</div>
      <div class="pi-info">
        <div class="pi-name">${esc(node.name)}</div>
        <div class="pi-ns">${esc(node.namespace)}</div>
        <div class="pi-uid">${esc((node.uid||'').slice(0,18))}…</div>
      </div>
      <div class="pi-badges">${badgesHtml}${node.alert_count>0?`<div class="badge info">${node.alert_count} alerts</div>`:''}</div>
    `;
    list.appendChild(div);
    if(expandedPod===node.uid){
      const stats=podStats(node);
      const exp=document.createElement('div');exp.className='pod-expand';
      if(stats.count===0){
        exp.innerHTML=`<div class="pe-row"><span class="pe-label">Status</span><span class="pe-val">No alerts recorded for this pod</span></div>`;
      } else {
        exp.innerHTML=`
          <div class="pe-row"><span class="pe-label">First Seen</span><span class="pe-val">${esc(stats.first.rule)} @ ${stats.first.timestamp?new Date(stats.first.timestamp).toTimeString().slice(0,8):'—'}</span></div>
          <div class="pe-row"><span class="pe-label">Last Seen</span><span class="pe-val">${esc(stats.last.rule)} @ ${stats.last.timestamp?new Date(stats.last.timestamp).toTimeString().slice(0,8):'—'}</span></div>
          <div class="pe-row"><span class="pe-label">Total Alerts</span><span class="pe-val">${stats.count}</span></div>
          <div class="pe-row"><span class="pe-label">Techniques</span><div class="pe-techs">${stats.techs.map(t=>stepBadge(t)).join('')}</div></div>
        `;
      }
      list.appendChild(exp);
    }
  });
}

let alertSortMode='time';
const SEV_RANK={CRITICAL:0,HIGH:1,MEDIUM:2};
function sortedAlertsView(){
  if(alertSortMode==='time') return alerts.slice().reverse();
  return alerts.slice().sort((a,b)=>{
    const r=(SEV_RANK[a.severity]??3)-(SEV_RANK[b.severity]??3);
    if(r!==0) return r;
    return new Date(b.timestamp||0)-new Date(a.timestamp||0);
  });
}
function setAlertSort(mode){
  alertSortMode=mode;
  document.getElementById('sort-time-btn').classList.toggle('active',mode==='time');
  document.getElementById('sort-sev-btn').classList.toggle('active',mode==='severity');
  renderAlerts(sortedAlertsView());
}
function renderAlerts(list){
  const feed=document.getElementById('alert-list');
  feed.innerHTML='';
  list.slice(0,50).forEach(a=>feed.appendChild(makeAlertEl(a)));
  document.getElementById('alert-count').textContent=list.length+' alerts';
}
function prependAlert(a){
  if(alertSortMode==='severity'){ renderAlerts(sortedAlertsView()); return; }
  const feed=document.getElementById('alert-list');
  feed.insertBefore(makeAlertEl(a),feed.firstChild);
  document.getElementById('alert-count').textContent=alerts.length+' alerts';
}
function makeAlertEl(a){
  const el=document.createElement('div');
  el.className=`alert-item ${a.severity}`;
  const ts=a.timestamp?new Date(a.timestamp).toTimeString().slice(0,8):'—';
  const podKey=(a.namespace||'')+'/'+(a.pod_name||'');
  const dotColor=a.pod_name?podColor(podKey):'#475569';
  el.innerHTML=`
    <div class="at"><span class="asev">${esc(a.severity)}</span><span class="arule" title="${esc(ruleTitle(a.rule))}">${esc(a.rule)}</span><span class="atime">${ts}</span></div>
    <div class="adesc">${esc(a.description||'')}</div>
    <div class="ameta">
      <span class="atag"><span class="pod-dot" style="background:${dotColor}"></span>${esc(a.namespace||'')}/${esc(a.pod_name||'')}</span>
      ${a.binary?`<span class="atag">${esc(a.binary)}</span>`:''}
      ${a.secret_name?`<span class="atag">secret:${esc(a.secret_name)}</span>`:''}
    </div>`;
  return el;
}

const EVT_LABELS={process_exec:'EXEC',k8s_secret_access:'AUDIT',pod_exec:'EXEC',network_connect:'NET'};
function prependEvent(ev){
  const stream=document.getElementById('evt-stream');
  const el=document.createElement('div');el.className='evt';
  el.style.background='rgba(59,130,246,.04)';
  const ts=ev.timestamp?new Date(ev.timestamp).toTimeString().slice(0,8):new Date().toTimeString().slice(0,8);
  const label=EVT_LABELS[ev.event_type]||ev.event_type;
  let body='';
  if(ev.event_type==='process_exec') body=ev.binary||'';
  else if(ev.event_type==='k8s_secret_access') body=`secret ${ev.verb} by ${ev.user||''}`;
  else if(ev.event_type==='pod_exec') body=`kubectl exec → ${ev.target_pod||''} by ${ev.user||''}`;
  else body=JSON.stringify(ev).slice(0,60);
  el.innerHTML=`<span class="et">${ts}</span><span class="ek ${ev.event_type}">${esc(label)}</span><span class="eb"><span class="ep">${esc(ev.pod_name||ev.namespace||'')}</span> · <span class="ebn">${esc(body)}</span></span>`;
  stream.insertBefore(el,stream.firstChild);
  setTimeout(()=>el.style.background='',500);
  while(stream.children.length>200) stream.removeChild(stream.lastChild);
}

setInterval(()=>{ document.getElementById('m-evts').textContent=evtMinBucket*6; evtMinBucket=0; },10000);

// ── Kill-chain stepper ──
const KC_STAGES=[
  {label:'Initial Access', rules:['T1021']},
  {label:'Execution',      rules:['T1059']},
  {label:'Priv. Escalation', rules:['T1548','T1548-PRIV-POD','T1611']},
  {label:'Lateral Movement', rules:['T1610']},
  {label:'Credential Access', rules:['T1552']},
  {label:'Impact',         rules:['T1496','T1499']},
  {label:'RBAC Abuse',     rules:['T1548.005']},
];
function populateKcPodSelect(){
  const sel=document.getElementById('kc-pod-select');
  const prev=sel.value;
  const withAlerts=gNodes.filter(n=>n.alert_count>0 && n.uid!=='admin' && n.uid!=='host' && !(n.uid||'').startsWith('rbac:'));
  const options=withAlerts.length?withAlerts:gNodes.filter(n=>n.name==='attacker');
  sel.innerHTML=options.map(n=>`<option value="${esc(n.name)}">${esc(n.namespace)}/${esc(n.name)}</option>`).join('');
  if(prev && options.some(n=>n.name===prev)) sel.value=prev;
  renderKillChain(sel.value||(options[0]&&options[0].name)||'attacker');
}
function renderKillChain(podName){
  if(!podName) return;
  const node=gNodes.find(n=>n.name===podName);
  const match=node?alerts.filter(a=>a.namespace===node.namespace&&a.pod_name===node.name):[];
  const rulesSeen=match.map(a=>a.rule).filter(Boolean);
  const el=document.getElementById('kc-steps');
  el.innerHTML=KC_STAGES.map(stage=>{
    const hitCount=rulesSeen.filter(r=>stage.rules.includes(r)).length;
    const hit=hitCount>0;
    return `<div class="kc-step ${hit?'hit':''}">
      <div class="kc-line"></div>
      <div class="kc-node">${hit?'✓':'—'}</div>
      ${hit?`<div class="kc-count">${hitCount}</div>`:''}
      <div class="kc-label">${esc(stage.label)}</div>
    </div>`;
  }).join('');
}

// ── MITRE Matrix page ──
const MATRIX_TECHNIQUES=[
  {id:'T1021', name:'Remote Services (kubectl exec)', tactic:'Lateral Movement'},
  {id:'T1059', name:'Shell spawned in container', tactic:'Execution'},
  {id:'T1611', name:'Escape to Host', tactic:'Priv. Escalation'},
  {id:'T1548', name:'Abuse Elevation (sudo/setcap)', tactic:'Priv. Escalation'},
  {id:'T1548-PRIV-POD', name:'Privileged pod deployed', tactic:'Priv. Escalation'},
  {id:'T1548.005', name:'RBAC cluster-admin grant', tactic:'Priv. Escalation'},
  {id:'T1552', name:'Secret read via K8s API', tactic:'Credential Access'},
  {id:'T1610', name:'Network Flow', tactic:'Lateral Movement'},
  {id:'T1613', name:'RBAC discovery burst', tactic:'Discovery'},
  {id:'T1496', name:'Cryptomining signature', tactic:'Impact'},
  {id:'T1499', name:'Fork-bomb / resource abuse', tactic:'Impact'},
];
const MATRIX_TACTICS=['Lateral Movement','Execution','Priv. Escalation','Credential Access','Discovery','Impact'];
function renderMitreMatrix(){
  const grid=document.getElementById('matrix-grid');
  const counts={};
  alerts.forEach(a=>{ if(a.rule) counts[a.rule]=(counts[a.rule]||0)+1; });
  grid.innerHTML='';
  MATRIX_TACTICS.forEach(t=>{
    const hd=document.createElement('div');
    hd.className='matrix-col-hd'; hd.textContent=t;
    grid.appendChild(hd);
  });
  const maxRows=Math.max(...MATRIX_TACTICS.map(tc=>MATRIX_TECHNIQUES.filter(x=>x.tactic===tc).length));
  MATRIX_TACTICS.forEach(tactic=>{
    const techs=MATRIX_TECHNIQUES.filter(x=>x.tactic===tactic);
    for(let i=0;i<maxRows;i++){
      const tech=techs[i];
      const cell=document.createElement('div');
      if(!tech){ cell.style.visibility='hidden'; grid.appendChild(cell); continue; }
      const count=counts[tech.id]||0;
      cell.className='matrix-cell'+(count>0?(count>=3?' hit':' hit-med'):'');
      cell.title=(MITRE_DESC[tech.id]||'')+' — click to view its alerts';
      cell.innerHTML=`<div><div class="matrix-cell-id">${esc(tech.id)}</div><div class="matrix-cell-name">${esc(tech.name)}</div></div><div class="matrix-cell-count">${count}</div>`;
      cell.onclick=()=>{ pendingRuleFilter=tech.id; navigate('alerts'); };
      grid.appendChild(cell);
    }
  });
}
function renderTechniqueBarChart(){
  const el=document.getElementById('tech-bar-chart');
  const counts={};
  alerts.forEach(a=>{ if(a.rule && !isChainRule(a.rule)) counts[a.rule]=(counts[a.rule]||0)+1; });
  const entries=Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  if(!entries.length){ el.innerHTML='<div class="table-empty">No individual technique alerts yet.</div>'; return; }
  const max=Math.max(1,...entries.map(e=>e[1]));
  el.innerHTML=entries.map(([rule,count])=>{
    const color=STEP_COLOR[rule]||'#3b82f6';
    return `<div class="bar-row"><span class="bar-label">${esc(rule)}</span><div class="bar-track"><div class="bar-fill" style="width:${(count/max*100)}%;background:${color}"></div></div><span class="bar-val">${count}</span></div>`;
  }).join('');
}

// ── Alerts page: full table with filter/search/sort/export ──
let sevFilter=new Set(), tableSortKey='timestamp', tableSortDir=-1, pendingRuleFilter=null;
function toggleSevFilter(s){
  if(sevFilter.has(s)) sevFilter.delete(s); else sevFilter.add(s);
  document.querySelectorAll('#page-alerts .chip[data-sev]').forEach(c=>c.classList.toggle('active',sevFilter.has(c.dataset.sev)));
  renderAlertsTable();
}
function populateRuleFilterOptions(){
  const sel=document.getElementById('alerts-rule-filter');
  if(!sel) return;
  const rules=[...new Set(alerts.map(a=>a.rule).filter(Boolean))].sort();
  const prev=pendingRuleFilter||sel.value;
  sel.innerHTML='<option value="">All rules</option>'+rules.map(r=>`<option value="${esc(r)}">${esc(r)}</option>`).join('');
  if(rules.includes(prev)) sel.value=prev;
  pendingRuleFilter=null;
}
function filteredAlerts(){
  const ruleSel=(document.getElementById('alerts-rule-filter')||{}).value||'';
  const q=((document.getElementById('alerts-search')||{}).value||'').toLowerCase();
  return alerts.filter(a=>{
    if(sevFilter.size && !sevFilter.has(a.severity)) return false;
    if(ruleSel && a.rule!==ruleSel) return false;
    if(q){
      const hay=[a.rule,a.description,a.pod_name,a.namespace,a.binary,a.user,a.secret_name].filter(Boolean).join(' ').toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  });
}
function setTableSort(key){
  if(tableSortKey===key) tableSortDir*=-1; else {tableSortKey=key; tableSortDir=-1;}
  renderAlertsTable();
}
function renderAlertsTable(){
  populateRuleFilterOptions();
  let list=filteredAlerts();
  list=list.slice().sort((a,b)=>{
    let av=a[tableSortKey], bv=b[tableSortKey];
    if(tableSortKey==='timestamp'){av=new Date(av||0).getTime();bv=new Date(bv||0).getTime();}
    if(tableSortKey==='severity'){av=SEV_RANK[a.severity]??3;bv=SEV_RANK[b.severity]??3;}
    if(av<bv) return -1*tableSortDir; if(av>bv) return 1*tableSortDir; return 0;
  });
  const tbody=document.getElementById('alerts-tbody');
  const MAX_ROWS=500;
  const shown=list.slice(0,MAX_ROWS);
  tbody.innerHTML=shown.map(a=>{
    const ts=a.timestamp?new Date(a.timestamp).toTimeString().slice(0,8):'—';
    const detail=[a.binary?`bin:${a.binary}`:'',a.secret_name?`secret:${a.secret_name}`:'',a.user?`user:${a.user}`:'',a.verb?`verb:${a.verb}`:''].filter(Boolean).join(' · ');
    return `<tr>
      <td class="mono">${esc(ts)}</td>
      <td><span class="sev-pill ${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td class="mono">${esc(a.rule)}</td>
      <td>${esc(a.pod_name||'—')}</td>
      <td>${esc(a.namespace||'—')}</td>
      <td>${esc(a.description||'')}</td>
      <td class="mono">${esc(detail)}</td>
    </tr>`;
  }).join('');
  const note=document.getElementById('alerts-table-note');
  if(!list.length){ tbody.innerHTML=''; note.textContent='No alerts match the current filters.'; return; }
  note.textContent = list.length>MAX_ROWS
    ? `Showing ${MAX_ROWS} of ${list.length} matching alerts — refine filters to narrow down.`
    : `${list.length} alert${list.length===1?'':'s'} matching current filters (of ${alerts.length} total).`;
}
function clearAlertFilters(){
  sevFilter.clear();
  document.querySelectorAll('#page-alerts .chip[data-sev]').forEach(c=>c.classList.remove('active'));
  document.getElementById('alerts-rule-filter').value='';
  document.getElementById('alerts-search').value='';
  renderAlertsTable();
}
function exportAlertsCsv(){
  const list=filteredAlerts();
  const cols=['timestamp','severity','rule','namespace','pod_name','description','binary','secret_name','user','verb'];
  const escCsv=v=>`"${String(v??'').replace(/"/g,'""')}"`;
  const rows=[cols.join(','), ...list.map(a=>cols.map(c=>escCsv(a[c])).join(','))];
  const blob=new Blob([rows.join('\n')],{type:'text/csv'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a'); a.href=url; a.download='cage_alerts_'+new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')+'.csv';
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}

// ── Chains Explorer page ──
const CHAIN_DEFS=[
  {key:'T1059>T1552', steps:['T1059','T1552'], desc:'Shell execution inside a pod followed by a Kubernetes secret read — the minimum viable lateral-movement-to-credential-theft pattern.'},
  {key:'T1021>T1059>T1552', steps:['T1021','T1059','T1552'], desc:'Full remote-exec chain: someone kubectl execs into a pod, spawns a shell, then reads a secret via the K8s API.'},
  {key:'T1059>T1610>T1552', steps:['T1059','T1610','T1552'], desc:'Shell spawn, then a network scan-like burst to other pods, then secret access — network-based lateral movement fused from eBPF and audit-log telemetry.'},
  {key:'T1059>T1548>T1611', steps:['T1059','T1548','T1611'], desc:'Shell access, privilege escalation inside the container, then a container-escape indicator — the classic breakout escalation path.'},
  {key:'T1611>T1552', steps:['T1611','T1552'], desc:'A container-escape indicator followed by credential access — theft of node-level or cluster secrets after breaking container isolation.'},
];
function renderChainsPage(){
  const grid=document.getElementById('chain-cards');
  const byKey={};
  alerts.filter(a=>a.severity==='CRITICAL'&&isChainRule(a.rule)).forEach(a=>{
    const k=chainKey(a.rule); byKey[k]=byKey[k]||[]; byKey[k].push(a);
  });
  grid.innerHTML=CHAIN_DEFS.map(def=>{
    const fired=byKey[def.key]||[];
    const last=fired.length?fired[fired.length-1]:null;
    return `<div class="chain-card ${fired.length?'fired':''}">
      <div class="chain-card-steps">${def.steps.map((s,i)=>stepBadge(s)+(i<def.steps.length-1?'<span class="chain-arrow">→</span>':'')).join('')}</div>
      <div class="chain-card-desc">${esc(def.desc)}</div>
      <div class="chain-card-stat"><span>${last?`Last fired ${esc(last.namespace)}/${esc(last.pod_name)} @ ${new Date(last.timestamp).toTimeString().slice(0,8)}`:'Not observed this session'}</span><span class="chain-card-count">${fired.length}</span></div>
    </div>`;
  }).join('');
  const tbody=document.getElementById('chains-history-tbody');
  const all=Object.values(byKey).flat().sort((a,b)=>new Date(b.timestamp||0)-new Date(a.timestamp||0));
  if(!all.length){ tbody.innerHTML='<tr><td colspan="4" class="table-empty">No correlated attack chains fired yet this session.</td></tr>'; return; }
  tbody.innerHTML=all.map(a=>`<tr>
    <td class="mono">${esc(a.timestamp?new Date(a.timestamp).toTimeString().slice(0,8):'—')}</td>
    <td>${splitChainSteps(a.rule).map(s=>stepBadge(s)).join('<span class="chain-arrow">→</span>')}</td>
    <td>${esc(a.namespace||'')}/${esc(a.pod_name||'')}</td>
    <td>${esc(a.description||'')}</td>
  </tr>`).join('');
}

// ── Pods page ──
let selectedPodDetail=null;
function renderPodsPage(){
  const q=((document.getElementById('pods-search')||{}).value||'').toLowerCase();
  const grid=document.getElementById('pods-grid');
  const nodes=gNodes.filter(n=>n.uid!=='admin'&&n.uid!=='host'&&!(n.uid||'').startsWith('rbac:'));
  const filtered=nodes.filter(n=>!q||n.name.toLowerCase().includes(q)||n.namespace.toLowerCase().includes(q));
  const sorted=filtered.slice().sort((a,b)=>{const s={critical:0,high:1,medium:2,clean:3};return (s[a.severity]||3)-(s[b.severity]||3);});
  grid.innerHTML=sorted.map(n=>{
    const color=SEV_COLORS[n.severity]||'#64748b';
    return `<div class="pod-card sev-${n.severity}" onclick="showPodDetail('${esc(n.uid)}')">
      <div class="pod-card-hd">
        <div class="pi-icon" style="background:${color}22;color:${color}">${esc(podInitials(n.name))}</div>
        <div><div class="pi-name">${esc(n.name)}</div><div class="pi-ns">${esc(n.namespace)}</div></div>
      </div>
      <div style="font-size:10px;color:var(--text3)">${n.alert_count||0} alerts</div>
    </div>`;
  }).join('');
  if(selectedPodDetail) showPodDetail(selectedPodDetail);
}
function showPodDetail(uid){
  selectedPodDetail=uid;
  const node=gNodes.find(n=>n.uid===uid);
  const el=document.getElementById('pod-detail-container');
  if(!node){ el.innerHTML=''; return; }
  const stats=podStats(node);
  const partners=new Set();
  gEdges.filter(e=>e.type==='T1610'&&(e.from===uid||e.to===uid)).forEach(e=>{
    const otherUid=e.from===uid?e.to:e.from;
    const other=gNodes.find(n=>n.uid===otherUid);
    if(other) partners.add(other.name);
  });
  const timeline=alerts.filter(a=>a.namespace===node.namespace&&a.pod_name===node.name).slice().reverse().slice(0,100);
  el.innerHTML=`<div class="pod-detail-panel">
    <div style="font-size:14px;font-weight:600;margin-bottom:10px">${esc(node.namespace)}/${esc(node.name)}</div>
    <div class="pe-row"><span class="pe-label">UID</span><span class="pe-val mono">${esc(node.uid)}</span></div>
    <div class="pe-row"><span class="pe-label">IP</span><span class="pe-val">${esc(node.ip||'—')}</span></div>
    <div class="pe-row"><span class="pe-label">Total Alerts</span><span class="pe-val">${stats.count}</span></div>
    ${stats.count?`<div class="pe-row"><span class="pe-label">First Seen</span><span class="pe-val">${esc(stats.first.rule)} @ ${new Date(stats.first.timestamp).toTimeString().slice(0,8)}</span></div>
    <div class="pe-row"><span class="pe-label">Last Seen</span><span class="pe-val">${esc(stats.last.rule)} @ ${new Date(stats.last.timestamp).toTimeString().slice(0,8)}</span></div>
    <div class="pe-row"><span class="pe-label">Techniques</span><div class="pe-techs">${stats.techs.map(t=>stepBadge(t)).join('')}</div></div>`:''}
    ${partners.size?`<div class="pe-row"><span class="pe-label">Network Partners (T1610)</span><span class="pe-val">${[...partners].map(esc).join(', ')}</span></div>`:''}
    <div class="ph" style="padding:8px 0;margin-top:10px;border:0">Alert Timeline</div>
    <div>${timeline.length?timeline.map(a=>`
      <div class="tl-item">
        <span class="tl-time">${esc(a.timestamp?new Date(a.timestamp).toTimeString().slice(0,8):'—')}</span>
        <div class="tl-body"><span class="sev-pill ${esc(a.severity)}">${esc(a.severity)}</span> ${stepBadge(a.rule)}<div class="tl-desc">${esc(a.description||'')}</div></div>
      </div>`).join(''):'<div class="table-empty">No alerts for this pod</div>'}
    </div>
  </div>`;
}

// ── Timeline page ──
let tlSevFilter=new Set();
function toggleTlSev(s){
  if(tlSevFilter.has(s)) tlSevFilter.delete(s); else tlSevFilter.add(s);
  document.querySelectorAll('#page-timeline .chip[data-sev]').forEach(c=>c.classList.toggle('active',tlSevFilter.has(c.dataset.sev)));
  renderTimelinePage();
}
function renderTimelinePage(){
  const q=((document.getElementById('tl-search')||{}).value||'').toLowerCase();
  const list=alerts.filter(a=>{
    if(tlSevFilter.size && !tlSevFilter.has(a.severity)) return false;
    if(q){const hay=[a.rule,a.description,a.pod_name].filter(Boolean).join(' ').toLowerCase(); if(!hay.includes(q)) return false;}
    return true;
  }).slice().reverse().slice(0,300);
  const el=document.getElementById('timeline-list');
  if(!list.length){ el.innerHTML='<div class="table-empty">No alerts match the current filters.</div>'; return; }
  const sevColor={CRITICAL:'#ef4444',HIGH:'#f59e0b',MEDIUM:'#eab308'};
  el.innerHTML=list.map(a=>{
    const podKey=(a.namespace||'')+'/'+(a.pod_name||'');
    const dot=sevColor[a.severity]||'#64748b';
    return `<div class="tl-item">
      <span class="tl-time">${esc(a.timestamp?new Date(a.timestamp).toTimeString().slice(0,8):'—')}</span>
      <div class="tl-rail"><div class="tl-dot" style="background:${dot}"></div></div>
      <div class="tl-body">
        <span class="tl-rule">${esc(a.rule)}</span>
        <div class="tl-desc">${esc(a.description||'')}</div>
        <div class="tl-pod"><span class="pod-dot" style="background:${podColor(podKey)}"></span>${esc(a.namespace||'')}/${esc(a.pod_name||'')}</div>
      </div>
    </div>`;
  }).join('');
}

// ── Health page ──
const SOURCE_LABEL={tetragon:'Tetragon eBPF',audit:'K8s Audit Log',network:'Network Monitor'};
function renderHealthPage(){
  if(!health){ document.getElementById('health-cards').innerHTML='<div class="table-empty">Loading…</div>'; return; }
  const cards=document.getElementById('health-cards');
  cards.innerHTML=Object.entries(health.sources).map(([key,s])=>{
    let statusClass='off', statusLabel='OFF';
    if(s.enabled){
      if(s.stale){statusClass='stale';statusLabel='STALE';}
      else if(s.last_seen===null){statusClass='off';statusLabel='WAITING';}
      else {statusClass='ok';statusLabel='LIVE';}
    }
    const ageText=s.age_seconds!=null?`${Math.round(s.age_seconds)}s ago`:'no events yet';
    return `<div class="health-card ${statusClass}">
      <div class="hc-title">${esc(SOURCE_LABEL[key]||key)}<span class="hc-status ${statusLabel}">${statusLabel}</span></div>
      <div class="hc-row"><span>Last event</span><span>${esc(ageText)}</span></div>
      <div class="hc-row"><span>Event count</span><span>${s.event_count}</span></div>
      ${s.process_alive!==null?`<div class="hc-row"><span>Subprocess</span><span>${s.process_alive?'running':'DEAD'}</span></div>`:''}
    </div>`;
  }).join('');
  document.getElementById('health-session-note').innerHTML=
    `<b>Ablation mode:</b> <span class="mono">${esc(health.ablation_mode)}</span><br><b>Event queue depth:</b> ${health.queue_size}<br><b>Server time:</b> ${esc(new Date(health.server_time).toLocaleString())}`;
}

// ── Routing / sidebar navigation ──
const PAGES=['live','graph','mitre','alerts','chains','pods','timeline','health'];
function switchPage(name){
  if(!PAGES.includes(name)) name='live';
  currentPage=name;
  PAGES.forEach(p=>{ const el=document.getElementById('page-'+p); if(el) el.classList.toggle('show',p===name); });
  document.querySelectorAll('.sidenav-item').forEach(it=>it.classList.toggle('active',it.dataset.page===name));
  if(name==='live'||name==='graph') moveGraphToPage(name);
  refreshCurrentPage();
}
function refreshCurrentPage(){
  if(currentPage==='mitre'){ renderMitreMatrix(); renderTechniqueBarChart(); }
  else if(currentPage==='alerts') renderAlertsTable();
  else if(currentPage==='chains') renderChainsPage();
  else if(currentPage==='pods') renderPodsPage();
  else if(currentPage==='timeline') renderTimelinePage();
  else if(currentPage==='health') renderHealthPage();
}
function navigate(name){ location.hash='#/'+name; }
function routeFromHash(){
  const h=(location.hash||'#/live').replace('#/','')||'live';
  switchPage(h);
}
window.addEventListener('hashchange',routeFromHash);

// ── Settings (localStorage) ──
let settings=Object.assign({refreshMs:5000, sound:false}, JSON.parse(localStorage.getItem('cage_settings')||'{}'));
function saveSettings(){ localStorage.setItem('cage_settings', JSON.stringify(settings)); }
function toggleSettingsPanel(){ document.getElementById('settings-panel').classList.toggle('show'); }
function updateRefresh(v){ settings.refreshMs=parseInt(v,10); saveSettings(); restartPolling(); }
function updateSound(v){ settings.sound=v; saveSettings(); }
let pollTimer=null;
function restartPolling(){
  if(pollTimer) clearInterval(pollTimer);
  pollTimer=setInterval(()=>{ fetchStats(); fetchGraph(); fetchHealth(); }, settings.refreshMs);
}

// ── Toast + optional sound on new CRITICAL alerts ──
function showToast(alert){
  const c=document.getElementById('toast-container');
  const el=document.createElement('div'); el.className='toast';
  el.innerHTML=`<div class="toast-title">⚠ ${esc(alert.severity)} — ${esc(alert.rule)}</div><div class="toast-body">${esc(alert.description||'')}<br><span style="color:var(--text3)">${esc(alert.namespace||'')}/${esc(alert.pod_name||'')}</span></div>`;
  c.appendChild(el);
  if(settings.sound) playBeep();
  setTimeout(()=>{ el.style.opacity='0'; el.style.transition='opacity .3s'; setTimeout(()=>el.remove(),300); },6000);
}
function playBeep(){
  try{
    const actx=new (window.AudioContext||window.webkitAudioContext)();
    const o=actx.createOscillator(), g=actx.createGain();
    o.connect(g); g.connect(actx.destination);
    o.frequency.value=880; g.gain.value=0.05;
    o.start(); o.stop(actx.currentTime+0.15);
  }catch(e){}
}

// ── Init ──
async function init(){
  document.getElementById('refresh-select').value=String(settings.refreshMs);
  document.getElementById('sound-toggle').checked=settings.sound;
  moveGraphToPage('live');
  await fetchAll();
  connectAlertStream();
  connectEventStream();
  await fetchHealth();
  restartPolling();
  routeFromHash();
}
init();
