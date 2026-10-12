const $ = s => document.querySelector(s);
const CSRF = document.querySelector('meta[name=csrf-token]').content;
const dry = () => $("#dry").checked;
let state = {selected:{}, mode:"clone", cloneSub:"reattach", cloneNsMode:"same", backup_path:null, backup_root:null, preview:null, ns:null, app:null};
let ctxInfo = {};
function isCloneApp(){ return state.mode==="clone" && state.cloneSub==="cloneapp"; }
function refOk(i){ return !!(i.nfs && isCloneApp()) || !!(i.new_ref||"").trim(); }

function badge(phase){
  const p=(phase||"").toLowerCase();
  const c = p==="bound"?"b-bound":p==="lost"?"b-lost":p==="pending"?"b-pending":"b-na";
  return `<span class="badge ${c}">${esc(phase||"—")}</span>`;
}
function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
// Cluster Kubernetes ACTIF: chaque requête le désigne (en-tête X-HYCU-Cluster) ;
// le serveur route kubectl vers ce cluster. “local” = cluster de la configuration.
let ACTIVE_CID="local", CLUSTERS=[{id:"local", name:"local", local:true}];
// Couche API unique: ne lève JAMAIS vers les handlers (une coupure réseau ou une
// réponse non-JSON renvoie {ok:false, error, status}), délai borné, bandeau hors-ligne.
let NET_DOWN=false;
function setNet(down){
  if(down===NET_DOWN) return; NET_DOWN=down;
  const b=$("#netBanner"); if(b) b.style.display = down ? "block": "none";
}
async function api(u, opts){
  const ctrl=new AbortController(); const t=setTimeout(()=>ctrl.abort(), (opts&&opts.timeout)||45000);
  try{
    const r=await fetch(u, Object.assign({signal:ctrl.signal}, opts||{}, {headers:Object.assign(
      {"X-HYCU-Cluster":(opts&&opts.cid)||ACTIVE_CID}, (opts&&opts.headers)||{})}));
    setNet(false);
    const txt=await r.text();
    let j=null; try{ j=txt?JSON.parse(txt):{}; }catch(e){ j=null; }
    if(j===null) return {ok:false, status:r.status, http_status:r.status, error:(r.status>=400?("HTTP "+r.status+" — "):"")+(txt||"unreadable response").slice(0,200)};
    if(j && typeof j==="object" && j.ok===undefined && j.error && r.status>=400) j.ok=false;
    // Le code HTTP est exposé à part: `status` appartient à la réponse du serveur
    // (statut d'un job HYCU, d'une comparaison d'objets…) et ne doit jamais être écrasé.
    if(j && typeof j==="object" && j.http_status===undefined) j.http_status=r.status;
    return j;
  }catch(e){
    const aborted = e && e.name==="AbortError";
    if(!aborted) setNet(true);
    return {ok:false, status:0, http_status:0, error: aborted ? "Timeout: the server is not responding.": "Server unreachable (network or tool stopped)."};
  }finally{ clearTimeout(t); }
}
async function get(u, cid){ return api(u, {cid}); }
async function post(u,b,cid){ return api(u, {method:"POST", cid, headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF}, body:JSON.stringify(b)}); }
window.addEventListener("unhandledrejection", e=>{ console.warn("Unhandled promise:", e.reason); });

// Erreurs actionnables: reconnaît les causes courantes (HYCU/Nutanix/kubectl/HTTP)
// et préfixe un conseil concret, en gardant le détail brut en dessous.
function errHint(raw){
  const e=(raw||"").toLowerCase();
  if(/401|unauthorized|password|invalid cred/.test(e)) return "Credentials rejected — check the username/password, or the HYCU API key (Help → API Keys, required with 2FA).";
  if(/\b403\b|forbidden|rbac/.test(e)) return "Access denied — insufficient rights (RBAC / API role).";
  if(/\b404\b|api-docs|endpoint.*not found/.test(e)) return "Endpoint not found — check the base URL and the API version (⚙ Settings).";
  if(/certificat|certificate|ssl|tls|self.?signed/.test(e)) return "TLS certificate — tick/untick “Verify the TLS certificate” in Connections to match your PKI.";
  if(/object storage/.test(e)) return "S3 endpoint unreachable — check the PORT (MinIO: 9000 = S3 API, not the 9001 console; Nutanix Objects: 443), the http/https scheme, and that the machine running the tool (the Pod, not your workstation) can reach that host.";
  if(/^(host|server) unreachable|timed out|connection (failed|refused)|getaddrinfo|name or service|errno \d+|10061|10060/.test(e)) return "Host unreachable — check the URL:port (HYCU 8443, Prism 9440), the network and the firewall.";
  if(/not connected|connect to at least|connect to hycu/.test(e)) return "Register the source first (⚙ at the top right).";
  if(/namespace.*not allowed/.test(e)) return "Namespace not in the allowed list — see ⚙ Settings → allowed namespaces.";
  if(/context.*not allowed|allowed_contexts/.test(e)) return "kubectl context not in the allowed list — see ⚙ Settings.";
  if(/context confirmation/.test(e)) return "Retype the exact target context name to confirm.";
  if(/jeton anti-csrf|csrf token/.test(e)) return "Reload the page (Ctrl+Shift+R): the security token has expired.";
  return "";
}
function errBox(raw){
  const h=errHint(raw);
  return `<div class="err">${h?`<b>${esc(h)}</b><div class="hint" style="margin-top:4px">${esc(raw||"")}</div>`:esc(raw||"error")}</div>`;
}

// Préférences mémorisées PAR NAVIGATEUR (localStorage): namespace, type d'opération,
// dossiers. Confort uniquement — jamais d'identifiant ni de secret ici.
const PREFS_KEY="hycu_prefs";
function prefs(){ try{ const p=JSON.parse(localStorage.getItem(PREFS_KEY)||"{}"); return (p && typeof p==="object" && !Array.isArray(p)) ? p: {}; }catch(e){ return {}; } }
function savePref(k,v){ try{ const p=prefs(); p[k]=v; localStorage.setItem(PREFS_KEY,JSON.stringify(p)); }catch(e){} }
function applyPrefs(){
  const p=prefs();
  if(p.bkDest) $("#bkDest").value=p.bkDest;
  if(p.backupRoot) $("#rsBackupRoot").value=p.backupRoot;
  if(p.customDir){ $("#rsCustomDir").checked=true; $("#rsCustomDirWrap").style.display="block"; }
  if(p.mode==="inplace"){ state.mode="inplace";
    document.querySelectorAll("#rsMode button").forEach(x=>x.classList.toggle("on",x.dataset.mode==="inplace"));
    $("#rsCloneSubWrap").style.display="none"; }
  if(p.ns && [...$("#bkNs").options].some(o=>o.value===p.ns)){ state.ns=p.ns; applyGlobalNs(); }
}

// Onglets
// Namespace GLOBAL synchronisé entre les 3 onglets (fluidité: un seul choix).
function applyGlobalNs(){ if(!state.ns) return; ["#bkNs","#rsNs","#vfNs"].forEach(id=>{ const e=$(id); if(e && e.value!==state.ns) e.value=state.ns; }); }
// Stepper du parcours Restaurer: surligne l'étape courante (1 Volumes, 2 Configurer, 3 Lancer).
function setRsStep(n){ document.querySelectorAll("#rsStepper .st").forEach(e=>{ const k=+e.dataset.st;
  e.classList.toggle("on",k===n); e.classList.toggle("done",k<n); }); }
// Pastilles cliquables du stepper: faire défiler vers la carte de l'étape (si affichée).
document.querySelectorAll("#rsStepper .st").forEach(s=>s.onclick=()=>{
  const n=+s.dataset.st;
  const el = n===1? document.querySelector("#tab-restore .card"): (n===2? $("#rsConfig"): $("#rsPlan"));
  if(el && el.style.display!=="none") el.scrollIntoView({behavior:"smooth",block:"start"});
});
const navBtns=[...document.querySelectorAll("nav button[data-tab]")];
// Pages (barre latérale) — navigation “à la HYCU”. Les opérations (sauvegarde,
// restauration, politique, sources) s'ouvrent en MODALES depuis une page, comme dans
// HYCU. switchTab() accepte encore les anciens noms d'onglet (backup/restore/connect)
// pour les appels programmés existants, et les redirige vers la modale correspondante.
const PAGES=["dashboard","apps","policies","jobs","verify","settings"];
let curPage="dashboard";
function switchTab(tab){
  if(tab==="connect") return openSources();
  if(tab==="restore") return openRestoreModal(state.ns);
  if(tab==="backup") return openBackupModal(state.ns?[state.ns]:[]);
  closeAllModals();
  if(tab!=="verify" && vfTrack) vfStop();           // le suivi auto ne survit pas à un changement de page
  const navTab = tab==="verify" ? "apps": tab;     // Vérification = sous-page d'Applications
  navBtns.forEach(x=>{ const on=x.dataset.tab===navTab; x.classList.toggle("on",on); x.setAttribute("aria-selected",on?"true":"false"); });
  PAGES.forEach(t=>$("#tab-"+t).style.display="none");
  $("#tab-"+tab).style.display="block";
  applyGlobalNs();                                   // la page ouverte reflète le namespace courant
  curPage=tab; onPageShown(tab);
  window.scrollTo({top:0});
}
navBtns.forEach(b=>b.onclick=()=>switchTab(b.dataset.tab));
$("#hdrConn").onclick=()=>openSources();

// ----- Fenêtre “À propos” (bouton ? de l'en-tête) -----
// “?”: menu Aide (guide dans un nouvel onglet) / À propos (modale existante).
async function openAbout(){
  const r=await get("/api/config");
  $("#aboutAudit").textContent=r.audit_log||"—";
  $("#aboutCfg").textContent=r.config_path||"—";
  $("#aboutBk").textContent=r.backup_root||"—";
  $("#aboutModal").style.display="flex";
}
function toggleHelpMenu(){
  const m=$("#helpMenu");
  if(m.style.display==="block"){ m.style.display="none"; return; }
  $("#clMenu").style.display="none"; $("#gearMenu").style.display="none";
  const r=$("#aboutBtn").getBoundingClientRect();
  m.style.right=Math.max(8, window.innerWidth-r.right-10)+"px";
  m.style.display="block";
}
$("#aboutBtn").onclick=e=>{ e.stopPropagation(); toggleHelpMenu(); };
document.querySelectorAll("#helpMenu .cli").forEach(el=>el.onclick=e=>{
  e.stopPropagation(); $("#helpMenu").style.display="none";
  if(el.dataset.act==="about") openAbout();
});
$("#aboutClose").onclick=()=>{ $("#aboutModal").style.display="none"; };

// ----- Barre “action suivante” du parcours Restaurer (anti-scroll) -----
// La page Restaurer est longue: cette barre flottante rend l'étape suivante
// visible en permanence (références à remplir -> prévisualiser -> lancer),
// sans que l'opérateur ait à chercher le bouton en bas de page.
function rsNext(txt, btnLabel, fn){
  $("#rsNextTxt").innerHTML=txt;
  const b=$("#rsNextBtn"); b.textContent=btnLabel; b.onclick=fn;
  $("#rsNextBar").classList.add("show");
}
function hideNextBar(){ $("#rsNextBar").classList.remove("show"); }
function scrollPulse(el){ if(!el) return; el.scrollIntoView({behavior:"smooth",block:"center"});
  el.classList.remove("pulse"); void el.offsetWidth; el.classList.add("pulse"); }
function updateNextBar(){
  if($("#tab-restore").style.display==="none") return hideNextBar();
  const chks=[...document.querySelectorAll(".rsChk:checked")];
  const slClone = typeof rsStatelessClone==="function" && rsStatelessClone();
  if(!chks.length && !slClone) return hideNextBar();
  if(slClone && $("#rsPlan").style.display==="none")
    return rsNext("Stateless application: no volume to choose.","Check the copy",()=>$("#rsPreview").click());
  const hyOn = conn.hycu && conn.hycu.connected;
  // Étape 3: plan affiché et lancement possible -> guider vers le bouton Lancer.
  if($("#rsPlan").style.display!=="none" && !$("#rsGo").disabled){
    return rsNext("Plan ready — final step:", $("#rsGo").textContent, ()=>scrollPulse($("#rsGo")));
  }
  // Orchestrated in-place restore: compte des points sélectionnés.
  if(state.mode==="inplace" && hyOn){
    const ready=chks.map(c=>c.dataset.pvc).filter(p=>rsInplaceSel[p]).length;
    if(ready===chks.length)
      return rsNext("All restore points are selected.","Go to launch",()=>scrollPulse($("#rsInplaceRun")));
    return rsNext(ready+" / "+chks.length+" restore point(s) selected.","Show the volumes",()=>scrollPulse($("#rsVolCfgs")));
  }
  // Clone / flux manuel: compte des références VG remplies.
  const items=collectItems();
  const filled=items.filter(refOk).length;
  if(filled===items.length)
    return rsNext("All VG references are filled.","Continue: review and launch",()=>$("#rsPreview").click());
  const batch=$("#hyBatchGo");   // panneau HYCU groupé disponible -> c'est l'action naturelle
  if(batch && !batch.disabled)
    return rsNext(filled+" / "+items.length+" VG reference(s) filled.","Restore the VGs from HYCU",()=>scrollPulse(batch));
  return rsNext(filled+" / "+items.length+" VG reference(s) filled.","Show the volumes",()=>scrollPulse($("#rsVolCfgs")));
}
// Navigation clavier des onglets (flèches gauche/droite + Home/Fin).
document.querySelector("nav").addEventListener("keydown",e=>{
  const i=navBtns.indexOf(document.activeElement); if(i<0) return;
  let j=-1;
  if(e.key==="ArrowRight") j=(i+1)%navBtns.length;
  else if(e.key==="ArrowLeft") j=(i-1+navBtns.length)%navBtns.length;
  else if(e.key==="Home") j=0;
  else if(e.key==="End") j=navBtns.length-1;
  if(j>=0){ e.preventDefault(); navBtns[j].focus(); navBtns[j].click(); }
});

// Bandeau simulation (source de vérité unique: #dry)
// E1: le mode simulation n'est proposé que si la configuration l'active
// (simulation_mode_available). Sinon l'interface travaille en mode réel, bandeau et
// interrupteur masqués; les garde-fous (confirmation du cluster, préflight) restent.
let SIM_AVAILABLE=false;
function applySimAvailability(avail){
  const was=SIM_AVAILABLE; SIM_AVAILABLE=!!avail;
  $("#dryBar").style.display = SIM_AVAILABLE ? "": "none";
  if(!SIM_AVAILABLE) $("#dry").checked=false;
  else if(!was) $("#dry").checked=true;          // simulation cochée par défaut quand elle est proposée
  refreshDry();
}
function refreshDry(){
  const live=!dry();
  $("#dryBar").classList.toggle("live",live);
  document.body.classList.toggle("realmode",live);   // barre rouge fixe + indicateur en-tête
  $("#dryLabel").textContent = live? "Simulation off — commands will be executed": "Simulation mode on";
  $("#dry").setAttribute("aria-checked", dry() ? "true": "false");
}
$("#dry").onchange=refreshDry;

// Modale de confirmation pour les actions destructives. Renvoie une Promise :
//  - false si annulé;  - true (ou le texte retapé) si confirmé.
// opts = { title, lines:[html…], requireText:(string|null) }
function confirmDanger(opts){
  const bgx=$("#dangerModal");
  if(bgx.style.display!=="none") return Promise.resolve(false);     // déjà ouverte: ignorer le double appel
  return new Promise(resolve=>{
    const bg=$("#dangerModal"), ok=$("#dmOk"), cancel=$("#dmCancel"), inp=$("#dmInput");
    $("#dmTitle").textContent=opts.title||"Confirm the real action";
    $("#dmBody").innerHTML=(opts.lines||[]).map(l=>`<div class="dm-line">${l}</div>`).join("");
    const need=opts.requireText||"";
    $("#dmConfirmWrap").style.display=need?"block":"none";
    $("#dmWord").textContent=need; inp.value="";
    function sync(){ ok.disabled = need ? (inp.value.trim()!==need): false; }
    sync(); inp.oninput=sync;
    bg.style.display="flex"; if(need) setTimeout(()=>inp.focus(),30);
    function close(val){ bg.style.display="none"; inp.oninput=null; ok.onclick=null; cancel.onclick=null; resolve(val); }
    ok.onclick=()=>close(need?inp.value.trim():true);
    cancel.onclick=()=>close(false);
  });
}

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// Rendu HTML d'un log d'étapes (UNIFIE les 4 rendus dupliqués: restore, in-place,
// clone-app, protect). Une entrée = {ok,dry,label,cmd,stdout,stderr,planned,job_id}.
function renderLog(log){
  return (log||[]).map(l=>{
    const ic = l.dry? '<span class="ic sim">○</span>': (l.ok?'<span class="ic ok">✓</span>':'<span class="ic ko">✕</span>');
    const planned = l.planned? ` <code style="font-size:11px;color:#888">${esc(JSON.stringify(l.planned.body||l.planned))}</code>`:'';
    const cmd = l.cmd? ` <code style="font-size:11px;color:#888">${esc(l.cmd)}</code>`:'';
    const detail = (l.stderr&&!l.ok)? ` — <span class="ko">${esc(l.stderr)}</span>` :
       (l.stdout? ` <span class="hint">${esc(l.stdout.length>200?l.stdout.slice(0,200)+'…':l.stdout)}</span>`:'');
    return `<div class="logline">${ic}<span><b>${esc(l.label||'')}</b>${l.job_id?(' · job '+esc(l.job_id)):''}${cmd}${planned}${detail}</span></div>`;
  }).join("");
}

// Lance une opération longue côté serveur et suit sa progression (polling), en
// rafraîchissant l'affichage à chaque tick. Renvoie le résultat final.
let CURRENT_OP=null;                 // {id, url, cid, ns} de l'opération suivie (persisté: reprise après F5)
const OP_KEY="hycu_op";
function rememberOp(o){ CURRENT_OP=o; try{ if(o) sessionStorage.setItem(OP_KEY, JSON.stringify(o)); else sessionStorage.removeItem(OP_KEY); }catch(e){} }
async function followOp(opId, onProgress){
  let errors=0;
  for(let i=0;i<6000;i++){            // garde-fou: ~90 min à 0,9 s
    const st = await get("/api/op_status?id="+encodeURIComponent(opId));
    if(!st.ok){
      if(st.http_status===0 || st.http_status>=500){   // coupure réseau / serveur: on réessaie (borné)
        if(++errors<=20){ await sleep(2000); continue; }
      }
      rememberOp(null);
      return {ok:false, error:st.error||"Operation tracking interrupted (the operation may still be running server-side)."};
    }
    errors=0;
    if(onProgress) onProgress(st.log||[], st.done);
    if(st.done){ rememberOp(null); return st.result || {ok:false, error:"Operation finished with no result."}; }
    await sleep(900);
  }
  rememberOp(null);
  return {ok:false, error:"Tracking timed out (the operation may still be running server-side)."};
}
async function runOp(url, body, onProgress){
  const start = await post(url, body);
  if(!start || !start.op_id){ return start || {ok:false, error:"Could not start the operation."}; }
  rememberOp({id:start.op_id, url, cid:ACTIVE_CID, ns:body&&body.namespace});
  return followOp(start.op_id, onProgress);
}
// Demande d'arrêt coopératif: le serveur termine l'étape (volume) en cours puis s'arrête proprement.
async function cancelCurrentOp(){
  if(!CURRENT_OP) return;
  const r=await post("/api/op_cancel",{id:CURRENT_OP.id});
  const el=$("#rsProgressTxt"); if(el) el.textContent = r.ok ? "Stop requested — finishing the current step…": (r.error||"Cannot stop");
}
// Reprise du suivi après rechargement: une opération encore en cours côté serveur est proposée.
async function resumeOps(){
  let saved=null; try{ saved=JSON.parse(sessionStorage.getItem(OP_KEY)||"null"); }catch(e){}
  const l=await get("/api/op_status");
  const running=(l&&l.running)||[];
  if(!running.length){ rememberOp(null); return; }
  const op = (saved && running.find(o=>o.op_id===saved.id)) || running[0];
  const banner=$("#opBanner"); if(!banner) return;
  banner.style.display="block";
  banner.innerHTML=`<div class="warnbox" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap"><span class="spin"></span>
    <b>An operation is running</b> (${esc(op.kind||"operation")}${op.ns?(" · "+esc(op.ns)):""}).
    <button class="btn ghost" id="opFollow">Follow</button></div><div id="opBannerLog"></div>`;
  $("#opFollow").onclick=async()=>{
    $("#opFollow").disabled=true;
    const r=await followOp(op.op_id, log=>{ $("#opBannerLog").innerHTML=renderLog(log); });
    $("#opBannerLog").innerHTML=(r.ok?'<div class="note">Operation finished.</div>':errBox(r.error||"Operation finished with errors."))+renderLog(r.log);
    banner.querySelector(".spin").style.display="none";
  };
}

// Init: contexte + namespaces + config
async function initApp(){
  await loadClusters();
  ctxInfo = await get("/api/context");
  renderCtx();
  renderKubeBanner();
  const n=await get("/api/namespaces");
  const opts = (n.namespaces||[]).map(x=>`<option>${esc(x)}</option>`).join("");
  ["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML = opts || "<option>—</option>");
  if(n.error){["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML="<option>kubectl ?</option>");}
  applyPrefs();                               // derniers choix de CE navigateur (ns, mode, dossiers)
  await loadConfig();
  loadAutoBackup();
  await loadConnStatus();                     // ATTENDRE que `conn` soit prêt (sinon la popup
  maybePromptUnlock();                        // de déverrouillage ne s'affichait jamais)
  onPageShown(curPage);                       // (re)charge les données de la page affichée
  resumeOps();                                // opération encore en cours côté serveur ?
}
// Accessibilité: associe chaque <label class="fld"> sans `for` au champ qui le suit
// (HTML statique et blocs rendus dynamiquement: observateur du DOM, débounce).
let _lblN=0, _lblT=null;
function linkLabels(){
  document.querySelectorAll("label.fld").forEach(l=>{
    if(l.getAttribute("for") || l.querySelector("input,select,textarea")) return;
    const el=l.nextElementSibling && (l.nextElementSibling.matches("input,select,textarea") ? l.nextElementSibling: l.nextElementSibling.querySelector("input,select,textarea"));
    if(!el) return;
    if(!el.id) el.id="fld-"+(++_lblN);
    l.setAttribute("for", el.id);
  });
}
linkLabels();
new MutationObserver(()=>{ clearTimeout(_lblT); _lblT=setTimeout(linkLabels, 150); }).observe(document.body, {childList:true, subtree:true});
(async()=>{
  ACTIVE_CID = prefs().cluster || "local";
  const cfg = await get("/api/config");
  ctxInfo = await get("/api/context");      // utilisé comme suggestion par l'assistant
  if(cfg && cfg.exists===false){ startWizard(); }
  await initApp();
})();
function maybePromptUnlock(){
  if(!conn || !conn.vault || !conn.vault.present) return;           // pas de coffre -> rien
  const anyConn = conn.hycu.connected || conn.nutanix.connected || conn.prismcentral.connected;
  if(anyConn) return;                                               // déjà connecté -> inutile
  if($("#wizard") && $("#wizard").style.display!=="none") return;   // l'assistant 1er lancement prime
  $("#unlock").style.display="flex";
  setTimeout(()=>$("#unlockPass").focus(),60);
}
$("#unlockSkip").onclick=()=>{ $("#unlockPass").value=""; $("#unlock").style.display="none"; };
$("#unlockPass").onkeydown=(e)=>{ if(e.key==="Enter") $("#unlockGo").click(); };
$("#unlockGo").onclick=async()=>{
  $("#unlockErr").innerHTML="";
  const b=$("#unlockGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>…';
  const r=await post("/api/creds/load",{passphrase:$("#unlockPass").value});
  $("#unlockPass").value=""; b.disabled=false; b.textContent="Unlock";
  if(!r.ok){ $("#unlockErr").innerHTML=errBox(r.error);
    setTimeout(()=>$("#unlockPass").focus(),30); return; }
  const names={hycu:"HYCU", nutanix:"Prism Element", prismcentral:"Prism Central", s3:"S3 object storage"};
  const lst=(r.loaded||[]).map(s=>names[s]||s).join(", ");
  const cls=(r.clusters||[]).join(", ");
  $("#unlockErr").innerHTML=`<div class="note">Connections reloaded: ${esc(lst||"none")}.`+
    (cls?`<br>Kubernetes clusters reloaded: ${esc(cls)}.`:"")+`</div>`;
  await loadConnStatus();
  await afterVaultLoad();
  setTimeout(()=>{ $("#unlock").style.display="none"; $("#unlockErr").innerHTML=""; }, 900);
};

// ----- Assistant de configuration (affiché si hycu_config.json est absent) -----
const wcfg = {kubectl_path:"kubectl", allowed_contexts:[], namespace_filter:[],
  require_context_confirm:true, wait_timeout:120, volume_handle_prefix:""};
let wizStep=0, wizSteps=[];

function wizFinalConfig(){
  return {kubectl_path:wcfg.kubectl_path, allowed_contexts:wcfg.allowed_contexts,
    namespace_filter:wcfg.namespace_filter, require_context_confirm:wcfg.require_context_confirm,
    wait_timeout:wcfg.wait_timeout,
    volume_handle_prefix:wcfg.volume_handle_prefix};
}
function buildWizSteps(){
  const ctx = ctxInfo.context || "";
  wizSteps = [
    {render:()=>`<h3>First-time setup</h3>
      <p class="q">No <code>hycu_config.json</code> file was found. A few questions
      to generate it — you can change everything later in the Settings page.</p>
      <div class="note" style="margin-top:14px">Detected kubectl context: <b>${esc(ctx||"unavailable")}</b></div>
      <div class="hint" style="margin-top:14px">Reinstalling an existing instance? <a href="#" id="wRestoreKit">Restore the tool from an S3 bucket</a></div>`,
     enter:()=>{ const rk=$("#wRestoreKit"); if(rk) rk.onclick=(e)=>{ e.preventDefault(); $("#wizard").style.display="none"; openSources("s3"); }; },
     commit:()=>{}},

    {render:()=>`<h3>Which kubectl binary should be used?</h3>
      <p class="q">Pick the distribution, or enter a custom command / path.</p>
      <div id="wKChips">${["kubectl","microk8s kubectl","k3s kubectl"].map(v=>
        `<span class="chip ${wcfg.kubectl_path===v?'sel':''}" data-v="${v}">${v}</span>`).join("")}</div>
      <label class="fld">kubectl command</label>
      <input type="text" id="wK" value="${esc(wcfg.kubectl_path)}">`,
     enter:()=>{document.querySelectorAll("#wKChips .chip").forEach(c=>c.onclick=()=>{
        $("#wK").value=c.dataset.v;
        document.querySelectorAll("#wKChips .chip").forEach(x=>x.classList.remove("sel")); c.classList.add("sel");});},
     commit:()=>{ wcfg.kubectl_path=($("#wK").value.trim()||"kubectl"); }},

    {render:()=>{const r=wcfg.allowed_contexts.length>0;
      return `<h3>Lock down the cluster(s)?</h3>
      <p class="q">Restricting the tool to specific kubectl contexts avoids acting on the wrong cluster by mistake.</p>
      <div class="wiz-opt ${!r?'sel':''}" data-mode="all"><b>All contexts</b><div class="d">No restriction.</div></div>
      <div class="wiz-opt ${r?'sel':''}" data-mode="restrict"><b>Restrict</b><div class="d">Allow only the listed contexts.</div></div>
      <div id="wCtxWrap" style="${r?'':'display:none'}"><label class="fld">Allowed contexts (commas)</label>
        <input type="text" id="wCtx" value="${esc(wcfg.allowed_contexts.join(', ')||ctx)}"></div>`;},
     enter:()=>{document.querySelectorAll('.wiz-opt[data-mode]').forEach(o=>o.onclick=()=>{
        document.querySelectorAll('.wiz-opt[data-mode]').forEach(x=>x.classList.remove('sel')); o.classList.add('sel');
        $("#wCtxWrap").style.display=o.dataset.mode==='restrict'?'block':'none';});},
     commit:()=>{ wcfg.allowed_contexts = document.querySelector('.wiz-opt[data-mode=restrict].sel')? csv($("#wCtx").value):[]; }},

    {render:()=>{const r=wcfg.namespace_filter.length>0;
      return `<h3>Limit to the relevant namespaces?</h3>
      <p class="q">You can expose only the application namespaces protected by HYCU.</p>
      <div class="wiz-opt ${!r?'sel':''}" data-mode="all"><b>All namespaces</b><div class="d">List every namespace in the cluster.</div></div>
      <div class="wiz-opt ${r?'sel':''}" data-mode="restrict"><b>Restrict</b><div class="d">Show only the listed namespaces.</div></div>
      <div id="wNsWrap" style="${r?'':'display:none'}"><label class="fld">Allowed namespaces (commas)</label>
        <input type="text" id="wNs" value="${esc(wcfg.namespace_filter.join(', '))}" placeholder="wordpress, bo-dev"></div>`;},
     enter:()=>{document.querySelectorAll('.wiz-opt[data-mode]').forEach(o=>o.onclick=()=>{
        document.querySelectorAll('.wiz-opt[data-mode]').forEach(x=>x.classList.remove('sel')); o.classList.add('sel');
        $("#wNsWrap").style.display=o.dataset.mode==='restrict'?'block':'none';});},
     commit:()=>{ wcfg.namespace_filter = document.querySelector('.wiz-opt[data-mode=restrict].sel')? csv($("#wNs").value):[]; }},

    {render:()=>`<h3>Safety check before real actions</h3>
      <p class="q">Recommended: require retyping the context name before any real restore.</p>
      <label class="wiz-opt ${wcfg.require_context_confirm?'sel':''}" id="wConfirmOpt">
        <input type="checkbox" id="wConfirm" ${wcfg.require_context_confirm?'checked':''} style="width:auto;margin-right:8px">
        <b>Require context confirmation</b><div class="d">The operator retypes the target context before acting.</div></label>`,
     enter:()=>{ $("#wConfirm").onchange=()=>$("#wConfirmOpt").classList.toggle('sel',$("#wConfirm").checked); },
     commit:()=>{ wcfg.require_context_confirm=$("#wConfirm").checked; }},

    {render:()=>`<h3>Advanced settings (optional)</h3>
      <p class="q">The defaults suit most environments.</p>
      <label class="fld">Wait timeout (s)</label><input type="text" id="wWait" value="${wcfg.wait_timeout}">
      <label class="fld">volumeHandle prefix (empty = auto-detected)</label>
      <input type="text" id="wVh" value="${esc(wcfg.volume_handle_prefix)}" placeholder="auto-detected from the existing PV">`,
     commit:()=>{ wcfg.wait_timeout=parseInt($("#wWait").value)||120;
        wcfg.volume_handle_prefix=$("#wVh").value.trim(); }},

    {final:true, render:()=>`<h3>Create the configuration</h3>
      <p class="q">Review then create <code>hycu_config.json</code> (editable later in ⚙ Settings).</p>
      <div class="wiz-recap">${esc(JSON.stringify(wizFinalConfig(),null,2))}</div>`,
     commit:()=>{}},
  ];
}
function startWizard(){ buildWizSteps(); wizStep=0; $("#wizard").style.display="flex"; renderWiz(); }
function renderWiz(){
  const s=wizSteps[wizStep];
  $("#wizBody").innerHTML=s.render();
  if(s.enter) s.enter();
  $("#wizBar").style.width=Math.round(wizStep/(wizSteps.length-1)*100)+"%";
  $("#wizStep").textContent=`Step ${wizStep+1} / ${wizSteps.length}`;
  $("#wizBack").style.visibility=wizStep===0?"hidden":"visible";
  $("#wizNext").textContent=s.final?"Create the configuration":"Next";
}
$("#wizBack").onclick=()=>{ if(wizStep>0){ wizSteps[wizStep].commit&&wizSteps[wizStep].commit(); wizStep--; renderWiz(); } };
$("#wizNext").onclick=async()=>{
  const s=wizSteps[wizStep]; if(s.commit) s.commit();
  if(s.final){
    const b=$("#wizNext"); b.disabled=true; b.innerHTML='<span class="spin"></span>Creating…';
    const r=await post("/api/config",{config:wizFinalConfig()});
    b.disabled=false; b.textContent="Create the configuration";
    if(!r.ok){ $("#wizBody").innerHTML+=`<div class="err">Failed: ${esc(r.error||'')}</div>`; return; }
    $("#wizard").style.display="none"; initApp(); return;
  }
  if(wizStep<wizSteps.length-1){ wizStep++; renderWiz(); }
};

// --------- Sauvegarde ---------
// Lien de téléchargement (.zip) d'un dossier de sauvegarde — permet de SORTIR une
// sauvegarde du conteneur/Pod vers le poste de l'opérateur (indispensable en Docker/K8s,
// où le serveur ne peut pas écrire sur le disque du client).
function dlBackupLink(dir, root, label){
  if(!dir) return "";
  const u="/api/backup/download?path="+encodeURIComponent(dir)+(root?("&root="+encodeURIComponent(root)):"")+"&cluster="+encodeURIComponent(ACTIVE_CID);
  return `<a class="btn ghost" href="${u}" download style="padding:2px 8px;font-size:12px;text-decoration:none;margin-left:6px">⬇ ${esc(label||'Download (.zip)')}</a>`;
}
// ----- Sauvegarde automatique de la configuration (onglet 1) -----
function abSyncLbl(){
  const on=$("#abEnabled").checked, l=$("#abEnabledLbl");
  l.textContent = on? "Enabled": "Disabled";
  l.style.color = on? "var(--good)": "var(--muted)";
}
$("#abEnabled").onchange=abSyncLbl;
function abRetSync(){
  const gfs=$("#abRet").value==="gfs";
  $("#abKeepWrap").style.display=gfs?"none":"";
  $("#abGfsWrap").style.display=gfs?"flex":"none";
}
$("#abRet").onchange=abRetSync;
function abRetLabel(s){
  return s.retention==="gfs"
    ? "GFS "+((s.gfs||{}).daily??7)+" d / "+((s.gfs||{}).weekly??4)+" wk / "+((s.gfs||{}).monthly??12)+" mo"
   : (s.keep===0 ? "unlimited (no counter)": (s.keep||15)+" versions");
}
async function loadAutoBackup(){
  const s=await get("/api/auto_backup");
  if(!s || !s.ok) return;
  $("#abEnabled").checked=!!s.enabled; abSyncLbl();
  $("#abInterval").value=Math.round(s.interval_hours||24);
  $("#abKeep").value=s.keep||15;
  $("#abRet").value=(s.retention==="gfs")?"gfs":"count";
  const g=s.gfs||{}; $("#abGfsD").value=g.daily??7; $("#abGfsW").value=g.weekly??4; $("#abGfsM").value=g.monthly??12;
  abRetSync();
  if(!$("#abDest").value) $("#abDest").value=s.dest||"";
  let txt = s.enabled? ("Every "+Math.round(s.interval_hours||24)+" h · retention: "+abRetLabel(s)+" per namespace."): "";
  if(s.running) txt+=" Backup in progress…";
  if(s.last_run) txt+=" Last: "+new Date(s.last_run*1000).toLocaleString()+" "+(s.last_ok?"✓":"✕")+" "+(s.last_summary||"");
  if(s.enabled) txt+= s.next_due? (" · Next: "+new Date(s.next_due*1000).toLocaleString()): " · First run in less than a minute.";
  $("#abStatus").textContent=txt;
}
$("#abSave").onclick=async()=>{
  const cfg={auto_backup_enabled:$("#abEnabled").checked,
    auto_backup_interval_hours:Math.max(0.25,parseFloat(String($("#abInterval").value).replace(",","."))||24),
    auto_backup_keep:Math.max(0,parseInt($("#abKeep").value)||0),
    auto_backup_retention:$("#abRet").value,
    auto_backup_keep_daily:Math.max(0,parseInt($("#abGfsD").value)||0),
    auto_backup_keep_weekly:Math.max(0,parseInt($("#abGfsW").value)||0),
    auto_backup_keep_monthly:Math.max(0,parseInt($("#abGfsM").value)||0),
    auto_backup_dest:$("#abDest").value.trim()};
  const r=await post("/api/config",{config:cfg});
  $("#abStatus").textContent = r.ok? "Saved.": ("Error: "+(r.error||""));
  setTimeout(loadAutoBackup, 700);
};
$("#bkRun").onclick=async()=>{
  const ns=$("#bkNs").value, b=$("#bkRun"), dest=$("#bkDest").value.trim();
  b.disabled=true; b.innerHTML='<span class="spin"></span>Backing up…';
  const r=await post("/api/backup",{ns, dest});
  b.disabled=false; b.textContent="Back up this namespace";
  if(!r.ok){$("#bkOut").innerHTML=errBox(r.error);return;}
  const rows=r.volumes.map(v=>{
    const vh=v.analysis&&v.analysis.old_volume_handle;
    const vgUuid=vh?(String(vh).match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/)||[null])[0]:null;
    const tag=vgUuid?`<span class="hint">(VG ${esc(vgUuid)})</span>`:(v.analysis&&v.analysis.old_iqn?'<span class="hint">(IQN detected)</span>':'');
    return `<li class="logline"><span class="ic ok">✓</span>
     <span><b>${esc(v.pvc)}</b> → PV ${esc(v.pv||"—")} ${tag}</span></li>`;
  }).join("");
  const resLine = (r.resources_count!=null)
    ? ` <span class="hint">+ ${r.resources_count} config resource(s) (Deployments, Services, Secrets…)${r.secrets==="encrypted"?" · Secrets encrypted":r.secrets==="redacted"?" · Secrets redacted":""}</span>`: "";
  const secWarn = r.secrets_warning ? `<div class="warnbox">⚠ ${esc(r.secrets_warning)}</div>`: "";
  $("#bkOut").innerHTML=`<div class="note">${r.count} volume(s) backed up to
     <code>${esc(r.dir)}</code>${resLine}${dlBackupLink(r.dir, r.root)}</div>${secWarn}<ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="warnbox">⚠ Get this backup <b>off the cluster</b> via ⬇ Download (.zip) — or copy the folder to other storage: it is your safety net in a disaster.</div>`;
};
$("#bkRunAll").onclick=async()=>{
  const b=$("#bkRunAll"), dest=$("#bkDest").value.trim();
  b.disabled=true; b.innerHTML='<span class="spin"></span>Backing up…';
  const r=await post("/api/backup_all",{dest});
  b.disabled=false; b.textContent="Back up all (filtered)";
  if(!r.ok){$("#bkOut").innerHTML=errBox(r.error);return;}
  const rows=(r.results||[]).map(x=>{
    if(x.ok) return `<li class="logline"><span class="ic ok">✓</span><span><b>${esc(x.ns)}</b> — ${x.count} volume(s) → <code>${esc(x.dir)}</code>${dlBackupLink(x.dir, r.root, 'Download')}</span></li>`;
    if(x.skipped) return `<li class="logline"><span class="ic sim">○</span><span><b>${esc(x.ns)}</b> — no PVC (skipped)</span></li>`;
    return `<li class="logline"><span class="ic ko">✕</span><span><b>${esc(x.ns)}</b> — ${esc(x.error||'failed')}</span></li>`;
  }).join("");
  const scope = r.filtered? "namespaces in the filter": "all cluster namespaces";
  $("#bkOut").innerHTML=`<div class="note">${r.backed_up}/${r.namespaces} namespace(s) backed up · ${r.volumes} volume(s) in total <span class="hint">(${scope})</span>.${dlBackupLink(r.root, r.root, 'Download all (.zip)')}</div>
     <ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="warnbox">⚠ Get these backups <b>off the cluster</b> via ⬇ Download — or copy the folders to other storage: it is your safety net in a disaster.</div>`;
};

// --------- Protection HYCU (assigner politique + sauvegarder) ---------
let bkMatches=[], bkMatchNs=null, bkNsList=[];   // bkNsList: namespaces ciblés (plusieurs applications en une fois)
function clearBkProtect(){ bkMatches=[]; bkMatchNs=null; $("#bkMatchOut").innerHTML=""; $("#bkProtectForm").style.display="none"; $("#bkProtectLog").innerHTML=""; }

// Re-protection HYCU après un clone: bascule sur l'onglet Back up, cible le bon
// namespace et lance l'analyse de correspondance (puis l'utilisateur choisit la politique).
function goReprotect(ns){
  openPolicyModal(ns || $("#bkNs").value);      // HYCU: “Set Policy” (analyse lancée d'office)
}
$("#bkNs").onchange=()=>{ state.ns=$("#bkNs").value; savePref("ns",state.ns); applyGlobalNs(); clearBkProtect(); };  // ns global + invalide l'analyse
$("#vfNs").onchange=()=>{ state.ns=$("#vfNs").value; savePref("ns",state.ns); applyGlobalNs(); };
$("#bkDest").addEventListener("change",()=>savePref("bkDest",$("#bkDest").value.trim()));
$("#bkMatch").onclick=async()=>{
  // Une application (namespace courant) ou PLUSIEURS (sélection de la page Applications) :
  // une analyse par namespace, un seul formulaire, un seul envoi à HYCU.
  const list = bkNsList.length ? bkNsList.slice(): [$("#bkNs").value];
  clearBkProtect();
  $("#bkMatchOut").innerHTML='<div class="hint">Analyzing…</div>';
  const results=[];
  for(const ns of list){
    const r=await get("/api/hycu/match?ns="+encodeURIComponent(ns));
    if(!r.ok){ $("#bkMatchOut").innerHTML=errBox((list.length>1?("Namespace “"+ns+"”: "):"")+r.error); return; }
    (r.matches||[]).forEach(m=>{ m.ns=r.namespace||ns; });
    results.push({ns:r.namespace||ns, matches:r.matches||[]});
  }
  bkMatches=results.flatMap(x=>x.matches); bkMatchNs=list.length===1 ? results[0].ns: null;
  const rowOf=m=>{
    let chk="", label="";
    if(m.volume_kind==="nfs"){
      // Volume NAS: partage HYCU (Nutanix Files ou NAS générique) au lieu d'un Volume Group.
      const shareLbl=`→ NAS share <b>${esc(m.hycu_share_name||"")}</b> <span class="hint">(${esc(m.hycu_file_server||m.nfs||"")})</span>`;
      if(m.match_kind==="exact"){
        chk=`<input type="checkbox" class="bkMchk" data-type="share" data-ns="${esc(m.ns)}" data-uuid="${esc(m.hycu_share_uuid)}" data-name="${esc(m.hycu_share_name||'')}" checked style="width:auto;margin-right:8px">`;
        label=shareLbl;
      } else if(m.match_kind==="name"){
        chk=`<input type="checkbox" class="bkMchk" data-type="share" data-kind="name" data-ns="${esc(m.ns)}" data-uuid="${esc(m.hycu_share_uuid)}" data-name="${esc(m.hycu_share_name||'')}" style="width:auto;margin-right:8px">`;
        label=shareLbl+' <span class="sim">same path, server to confirm</span>';
      } else if(m.match_kind==="ambiguous"){
        chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">⚠</span>`;
        label=`<span class="ko">ambiguous: several HYCU shares match ${esc(m.nfs||"")} — check in HYCU</span>`;
      } else {
        chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">✕</span>`;
        label=`<span class="ko">${m.error ? esc("HYCU shares unreadable: "+m.error): "no HYCU share for "+esc(m.nfs||"")+" — add this NAS in HYCU"}</span>`;
      }
    }
    else if(m.match_kind==="exact"){
      chk=`<input type="checkbox" class="bkMchk" data-ns="${esc(m.ns)}" data-uuid="${esc(m.hycu_vg_uuid)}" data-name="${esc(m.hycu_vg_name||'')}" data-ext="${esc(m.hycu_external_id||'')}" checked style="width:auto;margin-right:8px">`;
      label=`→ VG <b>${esc(m.hycu_vg_name||m.hycu_vg_uuid)}</b> <span class="hint">(externalId ${esc(m.hycu_external_id||'')})</span>`;
    } else if(m.match_kind==="name"){
      // data-kind: cocher cette ligne vaut CONFIRMATION du match par nom (transmise au serveur)
      chk=`<input type="checkbox" class="bkMchk" data-kind="name" data-ns="${esc(m.ns)}" data-uuid="${esc(m.hycu_vg_uuid)}" data-name="${esc(m.hycu_vg_name||'')}" data-ext="${esc(m.hycu_external_id||'')}" style="width:auto;margin-right:8px">`;
      label=`→ VG <b>${esc(m.hycu_vg_name||m.hycu_vg_uuid)}</b> <span class="sim">by name — to be confirmed</span>`;
    } else if(m.match_kind==="ambiguous"){
      chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">⚠</span>`;
      label=`<span class="ko">ambiguous: several Volume Groups match — check in HYCU</span>`;
    } else {
      chk=`<span class="ic ko" style="width:18px;display:inline-block;text-align:center;margin-right:8px">✕</span>`;
      label=`<span class="ko">no HYCU Volume Group found</span>`;
    }
    let prot="";
    if(m.matched){
      const cs=(m.compliancy||"").toUpperCase();
      const cb = cs==="GREEN"? '<span class="badge b-bound">compliant</span>'
              : cs==="RED"? '<span class="badge b-lost">non-compliant</span>'
              : '<span class="badge b-pending">to back up</span>';
      const unp = (m.protected && m.protected!=="PROTECTED")? ' <span class="badge b-pending">not protected</span>':'';
      prot=`<div class="meta">${cb}${unp} · policy: <b>${esc(m.policy||'none')}</b> · backups: ${m.has_backups?'yes':'no'}</div>`;
    }
    return `<li class="logline">${chk}<span style="flex:1"><b>${esc(m.pvc)}</b> ${label}${prot}</span></li>`;
  };
  const rows = list.length===1
    ? (bkMatches.map(rowOf).join("") || '<div class="hint">No PVC in this namespace.</div>')
   : results.map(x=>`<li class="logline" style="background:#F6F7FB;font-weight:700">${esc(x.ns)} <span class="hint" style="font-weight:400;margin-left:8px">${x.matches.length} PVC</span></li>`
        + (x.matches.map(rowOf).join("") || '<li class="logline"><span class="hint">No PVC in this namespace.</span></li>')).join("");
  const nx=bkMatches.filter(m=>m.match_kind==="exact").length, nn=bkMatches.filter(m=>m.match_kind==="name").length,
        na=bkMatches.filter(m=>m.match_kind==="ambiguous").length, n0=bkMatches.filter(m=>m.match_kind==="none").length;
  $("#bkMatchOut").innerHTML=`<ul class="pvc-list" style="margin-top:10px">${rows}</ul>
     <div class="hint">${nx} exact(s) · ${nn} by name (to confirm) · ${na} ambiguous · ${n0} not found</div>`;
  if(nx+nn>0){ $("#bkProtectForm").style.display="block"; loadBkPolicies(); updateBkHint(); }
};
// Liste des politiques HYCU de la modale “Set Policy”. NB: nom distinct de
// loadPolicies() (page Politiques) — deux déclarations homonymes se masqueraient.
async function loadBkPolicies(){
  const r=await get("/api/hycu/policies");
  $("#bkPolicy").innerHTML=`<option value="">(do not change the policy)</option>`+
    (r.ok? (r.policies||[]).map(p=>`<option value="${esc(p.uuid)}">${esc(p.name||p.uuid)}</option>`).join(""): "");
}
function updateBkHint(){ $("#bkProtectHint").textContent = dry()? "Simulation mode (banner at top): shows the HYCU calls.": ""; }
$("#dry").addEventListener("change",()=>{ if($("#bkProtectForm").style.display!=="none") updateBkHint(); });
$("#bkProtect").onclick=async()=>{
  const sel=[...document.querySelectorAll(".bkMchk:checked")];
  const vg_uuids=sel.map(c=>c.dataset.uuid);
  if(!vg_uuids.length){ $("#bkProtectLog").innerHTML='<div class="err">Tick at least one volume (“by name” matches must be confirmed).</div>'; return; }
  const live=!dry(), pol=$("#bkPolicy").value;
  const names=sel.map(c=>"• "+(c.dataset.name||c.dataset.uuid)+(c.dataset.ext?(" ("+c.dataset.ext+")"):""));
  if(live && !(await confirmDanger({title:"Confirm the HYCU protection", lines:[
     (pol?"Assign the policy then <b>back up</b>":"<b>Back up</b>")+" these Volume Groups:",
     "<b>"+names.map(esc).join("</b>, <b>")+"</b>"]}))) return;
  const b=$("#bkProtect"); b.disabled=true; b.innerHTML='<span class="spin"></span>…';
  const byName=sel.filter(c=>c.dataset.kind==="name").map(c=>c.dataset.uuid);   // cochés = confirmés par l'opérateur
  // Regroupement par namespace: la garde anti-stale du serveur est faite namespace par
  // namespace, puis UN SEUL appel HYCU (assignation) + UN SEUL lancement de sauvegarde.
  const byNs={};
  sel.forEach(c=>{ const k=c.dataset.ns||bkMatchNs||"";
    const it=(byNs[k]=byNs[k]||{namespace:k, vg_uuids:[], share_uuids:[], confirm_name_uuids:[]});
    (c.dataset.type==="share" ? it.share_uuids: it.vg_uuids).push(c.dataset.uuid);
    if(c.dataset.kind==="name") it.confirm_name_uuids.push(c.dataset.uuid); });
  const r=await post("/api/hycu/protect",{items:Object.values(byNs), namespace:bkMatchNs,
    vg_uuids:sel.filter(c=>c.dataset.type!=="share").map(c=>c.dataset.uuid),
    share_uuids:sel.filter(c=>c.dataset.type==="share").map(c=>c.dataset.uuid),
    policy_uuid:pol, dry:dry(), confirm_name_uuids:byName});
  b.disabled=false; b.textContent="Assign + back up now";
  if(!r.ok && !(r.steps&&r.steps.length)){ $("#bkProtectLog").innerHTML=errBox(r.error); return; }
  const lines=(r.steps||[]).map(s=> s.dry
    ? `<div class="logline"><span class="ic sim">○</span><span><b>${esc(s.label)}</b><pre class="box" style="margin-top:4px">${esc(JSON.stringify(s.planned,null,2))}</pre></span></div>`
   : `<div class="logline"><span class="ic ${s.ok?'ok':'ko'}">${s.ok?'✓':'✕'}</span><span><b>${esc(s.label)}</b>${s.job_id?(' · job '+esc(s.job_id)):''}${(s.error&&!s.ok)?(' — <span class="ko">'+esc(s.error)+'</span>'):''}</span></div>`
  ).join("");
  const head = r.dry? '<div class="warnbox">Simulation — calls that would be sent to HYCU:</div>'
    : (r.ok? '<div class="note">Request sent to HYCU: policy assigned, backup started. You can carry on — the job progress is shown below and in HYCU.</div>': '<div class="err">Failed — see details.</div>');
  $("#bkProtectLog").innerHTML=head+lines;
  if(!r.dry && r.ok && r.job_id){ $("#bkProtectLog").innerHTML+='<div id="bkJobProgress"></div>'; pollJobBar(r.job_id,"#bkJobProgress"); }
};

// --------- Restauration ---------
$("#rsNs").onchange=()=>{ state.ns=$("#rsNs").value; savePref("ns",state.ns); applyGlobalNs(); loadPvcs(); };
$("#rsCustomDir").onchange=()=>{ savePref("customDir",$("#rsCustomDir").checked); $("#rsCustomDirWrap").style.display=$("#rsCustomDir").checked?"block":"none"; if($("#rsNs").value) loadPvcs(); };
$("#rsBackupRoot").addEventListener("change",()=>{ savePref("backupRoot",$("#rsBackupRoot").value.trim()); if($("#rsCustomDir").checked && $("#rsNs").value) loadPvcs(); });
$("#rsBackupSel").onchange=applyBackupSelection;   // changer de sauvegarde de config sans re-fetch
let rsBackups = [];   // sauvegardes de config du namespace courant (la plus récente en premier)
let loadPvcsSeq=0;     // jeton anti-course: un fetch dépassé (autre namespace/cluster) est ignoré
async function loadPvcs(){
  const sel=$("#rsNs"); if(!sel.value) return;
  const ns=sel.value; state.ns=ns; state.pvcNs=ns; rsHyMatch=null; rsInplaceSel={}; invalidatePlan();
  if(state.app && state.app.ns!==ns){ state.app=null; $("#rsWizApp").innerHTML=rsAppLabel(); }   // autre namespace choisi: plus d'application ciblée
  const seq=++loadPvcsSeq;
  const customRoot = $("#rsCustomDir").checked ? $("#rsBackupRoot").value.trim(): "";
  state.backup_root = customRoot || null;
  const bk=await get("/api/backups?ns="+encodeURIComponent(ns)+(customRoot?("&root="+encodeURIComponent(customRoot)):""));
  if(seq!==loadPvcsSeq || state.ns!==ns) return;   // périmé: une autre application a été ouverte entre-temps
  if(bk.error && !bk.backups){ $("#rsPvcs").innerHTML=errBox(bk.error); return; }
  rsBackups = bk.backups || [];
  const wrap=$("#rsBackupSelWrap"), selEl=$("#rsBackupSel");
  if(rsBackups.length){
    selEl.innerHTML = rsBackups.map((b,i)=>{
      const idx=b.index||{}; const n=(idx.volumes||[]).length;
      const created=((idx.created||b.timestamp||"")+"").replace("T"," ").slice(0,19);
      const ctx=idx.context?(" · ctx "+idx.context):"";
      return `<option value="${i}">${esc(created)} — ${n} volume(s)${esc(ctx)}${i===0?" (most recent)":""}</option>`;
    }).join("");
    selEl.value="0"; wrap.style.display="block";
  }else{ selEl.innerHTML=""; wrap.style.display="none"; }
  await applyBackupSelection();
}
async function applyBackupSelection(){
  const ns=state.ns; state.selected={};
  const customRoot=state.backup_root, i=$("#rsBackupSel").value;
  let pvcs=[], src=customRoot?"custom folder":"cluster";
  if(rsBackups.length && i!=="" && rsBackups[i*1]){
    const b=rsBackups[i*1];
    state.backup_path=b.path;
    pvcs=((b.index||{}).volumes||[]).map(v=>({name:v.pvc,pv:v.pv,phase:"backed up",nfs:v.nfs?(v.nfs.server+":"+v.nfs.path):""}));
    src=customRoot?"backup (custom folder)":(i==="0"?"latest backup":"selected backup");
    const _dl=$("#rsBackupDl"); if(_dl){ _dl.href="/api/backup/download?path="+encodeURIComponent(b.path)+(customRoot?("&root="+encodeURIComponent(customRoot)):"")+"&cluster="+encodeURIComponent(ACTIVE_CID); _dl.style.display="inline"; }
  }else{
    state.backup_path=null;   // aucune sauvegarde -> repli live (vide si namespace détruit)
    const _dl=$("#rsBackupDl"); if(_dl) _dl.style.display="none";
    const live=await get("/api/pvcs?ns="+encodeURIComponent(ns));
    pvcs=live.pvcs||[];
  }
  renderRsPvcs(pvcs, src);
}
function renderRsPvcs(pvcs, src){
  $("#rsPvcs").innerHTML = pvcs.length? pvcs.map(p=>`
     <li><input type="checkbox" style="width:auto" class="rsChk" data-pvc="${esc(p.name)}" data-pv="${esc(p.pv||'')}"${p.nfs?' data-nfs="1"':''}>
       <div style="flex:1"><div class="nm">${esc(p.name)}${p.nfs?' <span class="badge b-na">NAS</span>':''}</div>
       <div class="meta">${p.nfs ? esc("NFS "+p.nfs)+" · data restored in HYCU (NAS share)": "PV "+esc(p.pv||'—')} · source: ${src}</div></div>${badge(p.phase)}</li>`).join("")
    : `<div class="hint">No volume. First back up this application's configuration (Applications → Back up).</div>`;
  document.querySelectorAll(".rsChk").forEach(c=>c.onchange=rebuildVolCfgs);
  $("#rsConfig").style.display="none"; $("#rsPlan").style.display="none"; setRsStep(1);
  // Assistant de restauration: comme dans HYCU, TOUS les volumes de l'application
  // sont présélectionnés (l'opérateur peut en décocher). Application ciblée (page
  // Applications): seuls SES volumes le sont — les autres applications du namespace
  // ne sont pas touchées par défaut.
  if(rsAutoCheck && pvcs.length){
    const only = state.app && state.app.pvcs && state.app.pvcs.length ? new Set(state.app.pvcs): null;
    document.querySelectorAll(".rsChk").forEach(c=>c.checked = (!c.dataset.nfs || isCloneApp()) && (!only || only.has(c.dataset.pvc)));
    if(only && ![...document.querySelectorAll(".rsChk")].some(c=>c.checked)) document.querySelectorAll(".rsChk").forEach(c=>c.checked=true);
    rebuildVolCfgs();
  }
  updateNextBar();
}
// Horodatage epoch en secondes (≈ `date -u +%s`): sert de suffixe UNIQUE à chaque clone,
// pour ne JAMAIS réutiliser un nom déjà créé (sinon: “le PVC/VG …-0000 existe déjà” au
// 2ᵉ clone de la même application). L'utilisateur peut éditer le champ ensuite.
function cloneStamp(){ return Math.floor(Date.now()/1000); }
function suggestName(pv){
  if(!pv) return "";
  return pv + "-" + cloneStamp();   // suffixe horodaté -> nom toujours unique et ≠ source
}
function rebuildVolCfgs(){
  const chks=[...document.querySelectorAll(".rsChk:checked")];
  if(!chks.length){$("#rsConfig").style.display="none";setRsStep(1);updateNextBar();return;}
  $("#rsConfig").style.display="block"; $("#rsPlan").style.display="none"; setRsStep(2);
  const ntOn = (conn.nutanix && conn.nutanix.connected) || (conn.prismcentral && conn.prismcentral.connected);
  const hyOn = conn.hycu && conn.hycu.connected;
  const inplaceOrch = hyOn && state.mode==="inplace";
  // Une carte ÉPURÉE par volume: à l'écran, seulement “volume → VG HYCU” et le
  // point de restauration (rempli en asynchrone par buildHyPanel). Tout le reste —
  // noms générés (VG cloné, nouveau PV) et saisie manuelle de la référence — vit
  // dans UN SEUL volet “Avancé” replié: ce sont des valeurs par défaut correctes.
  $("#rsVolCfgs").innerHTML = chks.map(c=>{
    const pvc=c.dataset.pvc, pv=c.dataset.pv;
    const vgNameRow = (hyOn && state.mode==="clone")
      ? `<label class="fld">Cloned VG name</label>
         <input type="text" class="hyVgName" data-pvc="${esc(pvc)}" value="${esc(pvc+'-'+cloneStamp())}">`: "";
    const nameRow = state.mode==="clone"
      ? `<label class="fld">New PV name</label>
         <input type="text" class="rsName" data-pvc="${esc(pvc)}" value="${esc(suggestName(pv))}">`: "";
    const ntRow = ntOn
      ? `<button class="btn ghost ntRefBtn" data-pvc="${esc(pvc)}" style="margin-top:6px">Search for the VG in Prism</button>
         <div class="ntpick" data-pvc="${esc(pvc)}"></div>`: "";
    const advOpen = hyOn ? "": "open";   // sans HYCU, la saisie manuelle est la seule voie -> volet ouvert
    const advSum = hyOn ? "Advanced (optional) — generated names, manual entry"
                       : "VG reference (required) & generated names";
    return `<div class="vol-cfg" data-pvc="${esc(pvc)}">
      <div class="nm">${esc(pvc)} <span class="hint">(PV ${esc(pv||'—')})</span> <span class="hint vgLabel" data-pvc="${esc(pvc)}" style="margin:0"></span> <span class="refStat hint" data-pvc="${esc(pvc)}" style="margin:0"></span></div>
      <div class="hySlot" data-pvc="${esc(pvc)}"></div>
      <details class="rsAdv" ${advOpen}>
        <summary class="rsAdvSum">${advSum}</summary>
        ${vgNameRow}${nameRow}
        <textarea class="rsRef" data-pvc="${esc(pvc)}" placeholder="5b4d284b-7109-4e82-4c71-7d0e36ecb5ab  (VG UUID, or NutanixVolumes-&lt;uuid&gt;, or legacy IQN)"></textarea>${ntRow}
      </details></div>`;
  }).join("");
  document.querySelectorAll(".ntRefBtn").forEach(b=>b.onclick=()=>ntFindRef(b.dataset.pvc));
  // Bouton global d'orchestration sur place (mode inplace + HYCU)
  $("#rsInplaceRunWrap").style.display = inplaceOrch? "block":"none";
  if(inplaceOrch) updateInplaceRunBtn();
  // “Continuer” (construit le plan): voie principale, sauf en sur-place orchestré
  // où le lancement se fait par le bouton dédié ci-dessus.
  $("#rsContinueWrap").style.display = inplaceOrch? "none":"block";

  // Guide en UNE ligne, adapté au cas (type d'opération + HYCU connecté ou non).
  let guide;
  if(state.mode==="inplace"){
    guide = hyOn
      ? "Choose a <b>restore point</b> per volume (the most recent is pre-selected), then <b>Launch the in-place restore</b>."
     : "Restore the VG in HYCU, paste its UUID per volume (<b>Advanced</b> section), then <b>Continue: review and launch</b>. <span class='hint'>Connect HYCU to automate.</span>";
  } else {
    guide = hyOn
      ? "Choose a <b>restore point</b> per volume (the most recent is pre-selected), then click <b>Restore the VGs from HYCU</b> — references and plan follow automatically."
     : "Clone each VG in HYCU, paste its UUID per volume (<b>Advanced</b> section), then <b>Continue: review and launch</b>. <span class='hint'>Connect HYCU to automate.</span>";
  }
  $("#rsFlowGuide").innerHTML = guide;
  // Barre “action suivante” + état des références en direct.
  document.querySelectorAll(".rsRef").forEach(t=>t.addEventListener("input",()=>{ invalidatePlan(); refreshRefStats(); syncContinueVisibility(); updateNextBar(); }));
  document.querySelectorAll(".rsName").forEach(t=>t.addEventListener("input",invalidatePlan));
  refreshRefStats();
  rsFullOrch=false;     // recalculé par buildHyPanel selon la couverture HYCU
  buildHyPanel();       // remplit les points de restauration (asynchrone) — rien si HYCU non connecté
  updateNextBar();
}
// “Continue: review and launch” n'est utile que pour le flux manuel: quand
// TOUS les volumes passent par le bouton HYCU groupé (plan automatique), on le
// masque pour ne laisser qu'UNE action à l'écran. Il réapparaît si l'utilisateur
// remplit les références à la main (volet Avancé).
let rsFullOrch=false;
function syncContinueVisibility(){
  const hyOn = conn.hycu && conn.hycu.connected;
  if(state.mode==="inplace" && hyOn){ $("#rsContinueWrap").style.display="none"; return; }
  const items=collectItems();
  const allFilled=items.length && items.every(refOk);
  $("#rsContinueWrap").style.display = (rsFullOrch && !allFilled)? "none":"block";
}
// État “référence remplie / à remplir” affiché à côté de chaque volume.
// En sur-place orchestré la référence n'est pas requise -> pas d'état.
function refreshRefStats(){
  const inplaceOrch = state.mode==="inplace" && conn.hycu && conn.hycu.connected;
  document.querySelectorAll(".refStat").forEach(el=>{
    const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(el.dataset.pvc)}"]`);
    const nasCopy = isCloneApp() && !!(document.querySelector(`.rsChk[data-pvc="${CSS.escape(el.dataset.pvc)}"]`)||{dataset:{}}).dataset.nfs;
    el.innerHTML = (inplaceOrch || nasCopy)? "" :
      ((ta && ta.value.trim())? '<span class="ok">✓ reference filled</span>': '<span class="sim">— reference to fill</span>');
  });
}
let rsHyMatch=null;   // cache de la correspondance PVC↔VG HYCU pour le namespace courant
let hyPanelSeq=0;     // jeton anti-rendu périmé (la sélection peut changer pendant les fetch)
// --------- Panneau HYCU groupé: TOUS les volumes cochés en un seul geste ---------
// Remplit le point de restauration DANS la carte de chaque volume (.hySlot), puis
// rend l'action globale (#rsHyActions). Clone: UN SEUL bouton “Restaurer les VG
// depuis HYCU” qui clone tout et remplit les références. Sur place: le point le
// plus récent est pré-sélectionné -> le lancement est prêt d'emblée.
async function buildHyPanel(){
  const actions=$("#rsHyActions");
  const hyOn = conn.hycu && conn.hycu.connected;
  const chks=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  actions.innerHTML="";
  if(!hyOn || !chks.length) return;
  const seq=++hyPanelSeq;
  document.querySelectorAll("#rsVolCfgs .hySlot").forEach(s=>
    s.innerHTML='<div class="hint" style="margin-top:4px"><span class="spin"></span> Searching for the HYCU Volume Group…</div>');
  const ns=$("#rsNs").value;
  if(!rsHyMatch || rsHyMatch.ns!==ns){
    const r=await get("/api/hycu/match?ns="+encodeURIComponent(ns));
    if(seq!==hyPanelSeq) return;
    if(!r.ok){ document.querySelectorAll("#rsVolCfgs .hySlot").forEach(s=>s.innerHTML=errBox(r.error)); return; }
    rsHyMatch={ns, matches:r.matches||[]};
  }
  const rows=await Promise.all(chks.map(async pvc=>{
    const m=(rsHyMatch.matches||[]).find(x=>x.pvc===pvc);
    if(m && m.volume_kind==="nfs") return {pvc, matched:false, nfs:m.nfs||"NFS", nfsRoot:(m.share_subpath||"/")==="/"};
    if(!m || !m.matched) return {pvc, matched:false};
    const rp=await get("/api/hycu/restorepoints?source="+encodeURIComponent(m.hycu_vg_uuid));
    return {pvc, matched:true, vg:m.hycu_vg_uuid, vgName:m.hycu_vg_name||"", kind:m.match_kind,
            points:(rp.ok?(rp.points||[]):[]), rpErr:(rp.ok?null:(rp.error||"restore points unavailable"))};
  }));
  if(seq!==hyPanelSeq) return;
  const isClone = state.mode==="clone";
  rows.forEach(r=>{
    const slot=document.querySelector(`#rsVolCfgs .hySlot[data-pvc="${CSS.escape(r.pvc)}"]`);
    if(!slot) return;
    const card=slot.closest(".vol-cfg");
    if(r.nfs){
      if(!isCloneApp()){
        slot.innerHTML='<div class="warnbox" style="margin-top:6px">'+esc("NAS volume ("+r.nfs+"): its data is restored in HYCU (NAS share). Untick it for this flow.")+'</div>';
        return;
      }
      slot.innerHTML = r.nfsRoot
        ? `<label class="fld">Data layout on the share</label>
           <select class="nasMode" data-pvc="${esc(r.pvc)}">
             <option value="ns_folder">One folder per namespace at the share root — the app writes into the folder named after its namespace</option>
             <option value="app_folders">The application keeps its own folders — restored under a folder named after the target namespace</option>
           </select>
           <div class="hint" style="margin-top:4px">${esc("NAS volume ("+r.nfs+"): HYCU restores the latest share backup; the copy's data lands in a folder named after the target namespace.")}</div>`
        : '<div class="hint" style="margin-top:6px">'+esc("NAS volume ("+r.nfs+"): HYCU restores the latest share backup into a folder named after the target namespace, keeping the tree the application saw.")+'</div>';
      return;
    }
    if(!r.matched){
      slot.innerHTML='<div class="warnbox" style="margin-top:6px">No HYCU Volume Group matched — paste the reference under “Advanced”.</div>';
      const d=card&&card.querySelector("details.rsAdv"); if(d) d.open=true;
      return;
    }
    const lbl=card&&card.querySelector(".vgLabel");
    if(lbl) lbl.innerHTML='→ HYCU VG <b>'+esc(r.vgName||r.vg)+'</b>'+(r.kind!=='exact'?' <span class="sim">(match '+esc(r.kind)+' — to verify)</span>':'');
    if(r.rpErr){ slot.innerHTML=`<div class="warnbox" style="margin-top:6px">${esc(r.rpErr)}</div>`; return; }
    if(!(r.points||[]).length){ slot.innerHTML='<div class="warnbox" style="margin-top:6px">No restore point for this VG.</div>'; return; }
    const opts=r.points.map((p,i)=>`<option value="${esc(p.id)}"${i===0?' selected':''}>${esc(p.time||p.id)}${p.status?(' · '+esc(p.status)):''}${i===0?' (most recent)':''}</option>`).join("");
    slot.innerHTML=`<label class="fld">Restore point</label>
      <select class="hyRp" data-pvc="${esc(r.pvc)}" data-vg="${esc(r.vg)}" data-name="${esc(r.vgName)}">${opts}</select>
      <div class="hyStat" data-pvc="${esc(r.pvc)}"></div>`;
    // Cloned VG name (volet Avancé): basé sur le VG source dès qu'on le connaît,
    // sauf si l'utilisateur a déjà touché au champ.
    const nameEl=card&&card.querySelector(".hyVgName");
    if(nameEl && !nameEl.dataset.touched && r.vgName) nameEl.value=r.vgName+"-"+cloneStamp();
  });
  document.querySelectorAll(".hyVgName").forEach(i=>i.oninput=()=>{ i.dataset.touched="1"; });
  const ready=rows.filter(r=>r.matched && !r.rpErr && (r.points||[]).length);
  if(isClone){
    if(ready.length){
      actions.innerHTML=
        `<div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
           <button class="btn" id="hyBatchGo">Restore the VGs from HYCU (${ready.length} volume(s))</button>
           <span class="hint" style="margin:0">Clones the VGs at the chosen point and fills the references — no data overwritten.</span>
         </div>`;
      $("#hyBatchGo").onclick=hyBatchRun;
    }
    const nas = isCloneApp() ? rows.filter(r=>r.nfs).length: 0;
    rsFullOrch = ready.length+nas===chks.length && ready.length>0;
    syncContinueVisibility();
  } else {
    // Sur place: pré-sélectionner le point le plus récent de chaque volume.
    rsInplaceSel={};
    ready.forEach(r=>{ rsInplaceSel[r.pvc]={source_vg_uuid:r.vg, restore_point_id:r.points[0].id, vg_name:r.vgName}; });
    document.querySelectorAll("#rsVolCfgs .hyRp").forEach(sel=>sel.onchange=()=>{
      rsInplaceSel[sel.dataset.pvc]={source_vg_uuid:sel.dataset.vg, restore_point_id:sel.value, vg_name:sel.dataset.name};
      updateInplaceRunBtn();
    });
    updateInplaceRunBtn();
  }
  updateNextBar();
}
// Remplit la référence d'un volume (textarea du volet Avancé) et rafraîchit les états.
function setRef(pvc, val){
  const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`);
  if(ta) ta.value=val;
  refreshRefStats(); updateNextBar();
}
// VG UUID cloné, retrouvé côté Nutanix par nom EXACT (ne jamais deviner :
// un mauvais VG = un mauvais volume attaché).
async function lookupVgUuid(vgName){
  if(!((conn.nutanix&&conn.nutanix.connected)||(conn.prismcentral&&conn.prismcentral.connected)))
    return {ok:false, err:"Connect Nutanix (Prism) to fetch the reference automatically, or use the Advanced section."};
  const r=await get("/api/nutanix/vgs?q="+encodeURIComponent(vgName||""));
  if(!r.ok || !(r.vgs||[]).length) return {ok:false, err:"VG “"+vgName+"” not found on the Nutanix side — use the Advanced section."};
  const exact=r.vgs.filter(v=>(v.name||"")===vgName);
  if(exact.length!==1) return {ok:false, err:(exact.length===0?"No":"Multiple")+" VG named exactly “"+vgName+"” — use the Advanced section to pick the right one."};
  if(!exact[0].uuid) return {ok:false, err:"VG found but UUID not exposed — use the Advanced section."};
  return {ok:true, uuid:exact[0].uuid, name:exact[0].name};
}
// Clone TOUS les volumes prêts dans HYCU (séquentiel: suivi lisible ligne par ligne),
// remplit les références, puis construit le plan automatiquement.
async function hyBatchRun(opts){
  opts = (opts && !(opts instanceof Event)) ? opts: {};
  const rows=[...document.querySelectorAll("#rsVolCfgs .vol-cfg")].map(div=>{
    const sel=div.querySelector(".hyRp"); if(!sel || !sel.value) return null;
    const nameEl=div.querySelector(".hyVgName");
    const newName=(nameEl&&nameEl.value.trim()) || ((sel.dataset.name||div.dataset.pvc)+"-"+cloneStamp());
    return {pvc:div.dataset.pvc, vg:sel.dataset.vg, rp:sel.value,
            newName, stat:div.querySelector(".hyStat")};
  }).filter(Boolean);
  if(!rows.length) return false;
  const live=!dry();
  if(live && !opts.skipConfirm && !(await confirmDanger({title:"Confirm the HYCU clones", lines:[
     "Trigger in HYCU the <b>clone</b> of <b>"+rows.length+"</b> Volume Group(s) at the chosen point?",
     "The source VGs are <b>not</b> modified — <b>new</b> VGs are created."]}))) return false;
  const b=$("#hyBatchGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>HYCU clones in progress…';
  hideNextBar();
  // Clones HYCU en PARALLÈLE (au plus 4 à la fois): chaque volume garde sa ligne de
  // suivi; HYCU exécute ses jobs indépendamment et l'endpoint serveur est sans verrou.
  async function cloneRow(row){
    row.stat.innerHTML='<div class="hint" style="margin-top:6px"><span class="spin"></span> HYCU clone…</div>';
    const body={namespace:rsHyMatch.ns, source_uuid:row.vg, restore_point_id:row.rp,
                mode:"clone", new_name:row.newName, dry:dry()};
    const r=await post("/api/hycu/restore",body);
    if(!r.ok){ row.stat.innerHTML=errBox(r.error); return false; }
    if(r.dry){
      row.stat.innerHTML=`<div class="warnbox" style="margin-top:6px">Simulation — HYCU call that would be sent:</div><pre class="box">${esc(JSON.stringify(r.planned,null,2))}</pre>`;
      // En simulation aucun VG n'est créé: on inscrit une référence PROVISOIRE (le VG
      // source) pour pouvoir dérouler l'aperçu du plan; en réel elle sera remplacée
      // par l'VG UUID cloné découvert.
      const m=((rsHyMatch&&rsHyMatch.matches)||[]).find(x=>x.pvc===row.pvc);
      if(m && m.nutanix_uuid){ setRef(row.pvc, m.nutanix_uuid);
        row.stat.innerHTML+='<div class="hint">Provisional reference (source VG) filled in for the simulation — replaced by the cloned VG in real mode.</div>'; }
      return true; }
    if(!r.job_id){ row.stat.innerHTML='<div class="warnbox" style="margin-top:6px">HYCU job not identified — fetch the reference via the Advanced section once the clone completes.</div>'; return false; }
    const ok=await pollJobBar(r.job_id, row.stat);
    if(!ok){ return false; }
    const lu=await lookupVgUuid(row.newName);
    if(!lu.ok){ row.stat.innerHTML+=`<div class="warnbox">${esc(lu.err)}</div>`; return false; }
    setRef(row.pvc, lu.uuid);
    row.stat.innerHTML=`<div class="note" style="margin-top:6px">✓ VG cloned — reference <code>${esc(lu.uuid)}</code> filled.</div>`;
    return true;
  }
  let failed=0, next=0;
  const worker=async()=>{ while(next<rows.length){ const row=rows[next++]; try{ if(!(await cloneRow(row))) failed++; }catch(e){ row.stat.innerHTML=errBox(String(e&&e.message||e)); failed++; } } };
  await Promise.all(Array.from({length:Math.min(4, rows.length)}, worker));
  b.disabled=false; b.textContent="Restore the VGs from HYCU ("+rows.length+" volume(s))";
  if(dry()) return false;                    // simulation: rien à préparer
  const items=collectItems();
  const allFilled=!!(items.length && items.every(refOk));
  const ok=!failed && allFilled;
  if(opts.noChain) return ok;
  if(ok){
    // Enchaîner directement: construire le plan et amener l'opérateur au lancement.
    $("#rsPreview").click();
  } else {
    updateNextBar();
  }
  return ok;
}
// --------- Orchestration RESTAURATION SUR PLACE (arrêt -> restore in-place -> redémarrage) ---------
let rsInplaceSel={};   // {pvc: {source_vg_uuid, restore_point_id, vg_name}}
function updateInplaceRunBtn(){
  const chosen=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  const ready=chosen.filter(p=>rsInplaceSel[p]);
  if(!$("#rsInplaceRun")) return;
  $("#rsInplaceRun").disabled = ready.length===0;
  $("#rsInplaceHint").textContent = ready.length
    ? (ready.length+" / "+chosen.length+" volume(s) ready"+(dry()?" · simulation":""))
   : "Select a restore point for each volume.";
  updateNextBar();
}
$("#dry").addEventListener("change",()=>{ if($("#rsInplaceRunWrap").style.display!=="none") updateInplaceRunBtn(); });
$("#rsInplaceRun").onclick=async()=>{
  const chosen=[...document.querySelectorAll(".rsChk:checked")].map(c=>c.dataset.pvc);
  const items=chosen.filter(p=>rsInplaceSel[p]).map(p=>({pvc:p, source_vg_uuid:rsInplaceSel[p].source_vg_uuid, restore_point_id:rsInplaceSel[p].restore_point_id}));
  if(!items.length) return;
  const live=!dry();
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res = await confirmDanger({title:"Confirm the in-place restore", requireText:needCtx, lines:[
       "Namespace: <b>"+esc((rsHyMatch?rsHyMatch.ns:$("#rsNs").value)||"?")+"</b>",
       "Target cluster: <b>"+esc(ctxInfo.context||"?")+"</b>",
       "The application will be <b>STOPPED</b>, the volumes restored <b>in-place</b> in HYCU (data overwritten by the chosen point), then the application <b>RESTARTED</b>."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  hideNextBar();   // pas de “prochaine action” pendant l'exécution
  const b=$("#rsInplaceRun"); b.disabled=true; b.innerHTML='<span class="spin"></span>Orchestrating…';
  $("#rsInplaceLog").innerHTML='<div class="hint"><span class="spin"></span> Starting…</div>';
  const ipBody={namespace:(rsHyMatch?rsHyMatch.ns:$("#rsNs").value), items, dry:dry()};
  if(live && ctxInfo.require_confirm) ipBody.confirm_context=confirmedCtx;
  const sess=rsSession, mine=()=>sess===rsSession;
  const r=await runOp("/api/orchestrate/inplace", ipBody,
    log=>{ if(mine()) $("#rsInplaceLog").innerHTML='<div class="hint"><span class="spin"></span> Orchestration in progress…</div>'+renderLog(log); });
  if(!mine()) return;
  b.disabled=false; b.textContent="Launch the in-place restore";
  if(r.error && !(r.log&&r.log.length)){ $("#rsInplaceLog").innerHTML=errBox(r.error); return; }
  const lines=renderLog(r.log);
  const head=r.dry?'<div class="warnbox">Simulation — sequence and HYCU calls that would be executed.</div>'
    :(r.aborted?'<div class="err"><b>Sequence aborted</b> — the application was left stopped. See details.</div>'
      :(r.ok?'<div class="note">In-place restore complete.</div>':'<div class="err">Some steps failed — see details.</div>'));
  $("#rsInplaceLog").innerHTML=head+lines;
  if(!r.dry && r.ok && !r.aborted) rsFinish(ipBody.namespace, false, sess);
};
document.querySelectorAll("#rsMode button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#rsMode button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); state.mode=b.dataset.mode; savePref("mode",state.mode);
  $("#rsCloneSubWrap").style.display = state.mode==="clone"?"block":"none";
  rebuildVolCfgs();
});
document.querySelectorAll("#rsCloneSub button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#rsCloneSub button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); state.cloneSub=b.dataset.sub;
  $("#rsCloneAppWrap").style.display = state.cloneSub==="cloneapp"?"block":"none";
  $("#rsPlan").style.display="none";
});
document.querySelectorAll("#rsCloneNsMode button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#rsCloneNsMode button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); state.cloneNsMode=b.dataset.nsmode;
  $("#rsCloneSuffixWrap").style.display = state.cloneNsMode==="same"?"block":"none";
  $("#rsCloneTargetWrap").style.display = state.cloneNsMode==="other"?"block":"none";
  $("#rsCloneRefsWrap").style.display = state.cloneNsMode==="other"?"block":"none";
});
function cloneAppBody(){
  const same = state.cloneNsMode==="same";
  return {namespace:$("#rsNs").value, items:collectItems(), backup_path:state.backup_path, backup_root:state.backup_root,
          app: (state.app && !state.app.unassigned) ? state.app.name: undefined,   // application ciblée: tous ses workloads
          target_namespace: same? "": $("#rsCloneTargetNs").value.trim(),
          suffix: same? ($("#rsCloneSuffix").value.trim()||"-clone"): "",
          clone_refs: same? false: !!($("#rsCloneRefs")&&$("#rsCloneRefs").checked)};
}
function cloneWarnings(ws){
  // Le résumé liste déjà les dépendances clonées: seules les limites restent, en une ligne.
  return (ws||[]).filter(w=>!/^Dependencies automatically cloned/.test(w)).map(w=>`<div class="hint" style="margin-top:6px">${esc(w)}</div>`).join("");
}
function renderCloneAppPlan(r){
  if(!r.ok && !r.preview){ $("#rsErr").innerHTML=errBox(r.error); return; }
  const p=r.preview||{};
  let html=`<div class="repl"><div class="nm">Copy → namespace <b>${esc(p.target_namespace)}</b>${p.same_namespace?' (suffix)':''}</div>
     ${(p.pvcs||[]).length?`<div><span class="k">Volumes</span>: ${esc(p.pvcs.join(', '))}</div>`:''}
     <div><span class="k">Applications</span>: ${esc((p.workloads||[]).join(', ')||'none')}</div>
     ${(p.dependencies&&p.dependencies.length)?`<div><span class="k">Dependencies</span>: ${esc(p.dependencies.join(', '))}</div>`:''}</div>`;
  html+=cloneWarnings(r.warnings);
  if(r.manifests_preview){ html+=`<details style="margin-top:6px"><summary class="hint">View the manifests</summary><pre class="box">${esc(r.manifests_preview)}</pre></details>`; }
  $("#rsRepl").innerHTML=html;
  $("#rsSteps").innerHTML="";
  $("#rsPlan").style.display="block"; setRsStep(3);
  updateGoButton(r.ok);
  if($("#mRestore").style.display!=="none") rsShowPage("plan");
  else $("#rsPlan").scrollIntoView({behavior:"smooth",block:"start"});
}

function collectItems(){
  const items=[];
  document.querySelectorAll(".rsChk:checked").forEach(c=>{
    const pvc=c.dataset.pvc;
    const ref=(document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`)||{}).value||"";
    const nameEl=document.querySelector(`.rsName[data-pvc="${CSS.escape(pvc)}"]`);
    const modeEl=document.querySelector(`.nasMode[data-pvc="${CSS.escape(pvc)}"]`);
    items.push({pvc, new_ref:ref, new_name:nameEl?nameEl.value:"", nfs:!!c.dataset.nfs, nas_mode:modeEl?modeEl.value:""});
  });
  return items;
}

$("#rsPreview").onclick=async()=>{
  $("#rsErr").innerHTML="";
  const items=collectItems();
  if(!items.length && !rsStatelessClone()){$("#rsErr").innerHTML='<div class="err">Tick at least one PVC.</div>';return;}
  if(isCloneApp()){
    if(state.cloneNsMode==="other" && !$("#rsCloneTargetNs").value.trim()){ $("#rsErr").innerHTML='<div class="err">Provide the target namespace.</div>'; return; }
    const cb=cloneAppBody(); cb.dry=true;
    const r=await runOp("/api/clone_app",cb);
    state.preview={_cloneapp:true};
    renderCloneAppPlan(r);
    return;
  }
  const body={namespace:$("#rsNs").value,mode:state.mode,items,backup_path:state.backup_path,backup_root:state.backup_root,dry:dry()};
  const r=await post("/api/prepare_restore",body);
  if(!r.ok && !(r.results||[]).length){ $("#rsErr").innerHTML=errBox(r.error||"Preparation failed."); updateGoButton(false); return; }
  state.preview=body;
  let html="";
  (r.results||[]).forEach(res=>{
    if(!res.ok){html+=`<div class="err"><b>${esc(res.pvc)}</b>: ${esc(res.error)}</div>`;return;}
    const REPL_LABEL={vg_uuid:"VG UUID", pv_name:"PV name", volumeHandle:"volumeHandle"};   // clés stables -> libellés
    const repl=(res.replacements||[]).map(([k,o,n])=>`<div><span class="k">${esc(REPL_LABEL[k]||k)}</span> :
       <span class="old">${esc(o)}</span> → <span class="new">${esc(n)}</span></div>`).join("")||
       '<div class="hint">No string change.</div>';
    const warn = res.warn? `<div class="warnbox">⚠ ${esc(res.warn)}</div>`: "";
    html+=`<div class="repl"><div class="nm">${esc(res.pvc)} → PV ${esc(res.new_pv_name)}</div>${repl}
       <div><span class="k">derived volumeHandle</span>: <span class="new">${esc(res.new_volume_handle)}</span></div>${warn}
       <details style="margin-top:6px"><summary class="hint">View the full manifest of the new PV</summary>
       <pre class="box">${esc(res.manifest_preview)}</pre></details></div>`;
  });
  $("#rsRepl").innerHTML=html;
  $("#rsSteps").innerHTML=(r.planned_steps||[]).map(s=>`<li class="${/^(Delete|Stop)/.test(s)?'danger':''}">${esc(s)}</li>`).join("");
  $("#rsPlan").style.display="block"; setRsStep(3);
  if(!r.ok){$("#rsErr").innerHTML='<div class="err">Fix the volumes in error before launching.</div>';}
  updateGoButton(r.ok);
  if($("#mRestore").style.display!=="none") rsShowPage("plan");       // page 3 de l'assistant
  else $("#rsPlan").scrollIntoView({behavior:"smooth",block:"start"});
};
// Toute modification des références/noms rend le plan périmé: il faut re-prévisualiser.
function invalidatePlan(){
  if(rsDone) return;                       // parcours finished: rien à relancer
  if(!state.preview) return;
  state.preview=null; $("#rsPlan").style.display="none"; $("#rsLog").innerHTML="";
  if(typeof rsWizPage!=="undefined" && rsWizPage==="plan") rsShowPage("form");
  setRsStep(2);
}

let rsRunning=false;
$("#rsCancel").onclick=()=>{ $("#rsCancel").disabled=true; cancelCurrentOp(); };
// Liste ✓/✕ du préflight renvoyée par le serveur (contrôles AVANT tout stopping of l'application).
function renderPreflight(checks){
  if(!checks || !checks.length) return "";
  return `<details class="preflight" ${checks.some(c=>c.ok===false)?"open":""}><summary><b>Preflight</b> — ${checks.filter(c=>c.ok!==false).length}/${checks.length} checks passed</summary>
    <ul class="pvc-list">${checks.map(c=>`<li class="logline">${stIc(c.ok===false?"ko":(c.ok===null?"na":"ok"), c.ok===false?"Failed":"OK")}<span><b>${esc(c.name)}</b>${c.detail?(' — <span class="hint">'+esc(c.detail)+'</span>'):''}</span></li>`).join("")}</ul></details>`;
}
function updateGoButton(ready){
  refreshDry();
  const live=!dry();
  const needConfirm = live && ctxInfo.require_confirm;
  $("#rsCtxConfirm").style.display = "none";          // la confirmation se fait dans la boîte de dialogue
  $("#rsGoHint").textContent = live? "": "Simulation mode: nothing will be changed.";
  $("#rsGo").className = live? "btn danger": "btn";
  const kind = state.mode!=="clone" ? "inplace": (isCloneApp() ? "cloneapp": "clone");
  $("#rsGo").textContent = live
    ? {inplace:"Restore in place", clone:"Restore to the new volumes", cloneapp:"Launch the application clone"}[kind]
   : {inplace:"Simulate the in-place restore", clone:"Simulate the restore", cloneapp:"Simulate the application clone"}[kind];
  $("#rsGo").disabled = !ready;
  updateNextBar();
}
$("#dry").addEventListener("change",()=>{ if($("#rsPlan").style.display!=="none") updateGoButton(!$("#rsGo").disabled); });


// ----- Clone d'application: confirmation unique, exécution, état “finished” -----
let rsDone=false, rsDoneTarget="", cloneBusy=false;
// Chaque ouverture de la fenêtre de restauration est une “session”: une opération
// lancée dans une session précédente (fenêtre fermée en cours de route) n'écrit plus
// dans les journaux et ne termine plus l'assistant de la nouvelle ouverture.
let rsSession=0;
function rsNewSession(){
  rsSession++; rsDone=false; cloneBusy=false; state.preview=null;
  $("#rsProgress").style.display="none"; $("#rsCloneTargetNs").value="";
  document.querySelectorAll("#drForm input, #drForm select").forEach(e=>e.disabled=false);
}
// Fin RÉUSSIE d'une opération réelle, quel que soit le parcours: seul “Vérifier” reste.
// `stay`: quelque chose est à lire (avertissements, re-protection) -> pas de bascule auto.
function rsFinish(ns, stay, sess, slow){
  if(sess!==undefined && sess!==rsSession) return;        // opération d'une ouverture précédente
  rsDone=true; rsDoneTarget=ns||state.ns||"";
  setRsStep(4);
  // Plus rien de relançable une fois finished (bouton HYCU de la page DR, champs).
  $("#drAutoWrap").style.display="none";
  document.querySelectorAll("#drForm input, #drForm select").forEach(e=>e.disabled=true);
  rsWizSync();
  if(!stay) setTimeout(()=>{ if(rsDone && sess===rsSession && $("#mRestore").style.display!=="none") gotoVerify(rsDoneTarget, true); }, slow ? 4000: 1500);
}
function confirmCloneApp(withHycu){
  const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
  const tgt = state.cloneNsMode==="same" ? "in the <b>same namespace</b> (with a suffix)"
           : "in namespace <b>"+esc($("#rsCloneTargetNs").value.trim()||"?")+"</b>";
  const lines=[];
  if(withHycu) lines.push("Clone the Volume Groups in HYCU at the chosen points (the original volumes are not modified).");
  lines.push("Create a copy of the application "+tgt+" — the original application is neither modified nor stopped.");
  lines.push("Cluster: <b>"+esc(ctxInfo.context||"?")+"</b>");
  return confirmDanger({title:"Confirm the application clone", requireText:needCtx, lines});
}
async function runCloneApp(confirmedCtxCA){
  const live=!dry(), sess=rsSession, mine=()=>sess===rsSession;
  rsDone=false;
  const bb=$("#rsGo"); bb.disabled=true; bb.innerHTML='<span class="spin"></span>…';
  $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Starting…</div>';
  const caBody={...cloneAppBody(), dry:dry()};
  if(live && ctxInfo.require_confirm) caBody.confirm_context=confirmedCtxCA;
  const r=await runOp("/api/clone_app", caBody,
    log=>{ if(mine()) $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Cloning in progress…</div>'+renderLog(log); });
  if(!mine()) return;
  bb.disabled=false; updateGoButton(true);
  if(r.error && !(r.log&&r.log.length)){ $("#rsLog").innerHTML=errBox(r.error); return; }
  const lns=renderLog(r.log);
  const hd=r.dry?'<div class="note">Simulation — resources that would be created (the original app stays intact).</div>'
    :(r.ok?'<div class="note">Application copy finished. The original application is intact.</div>':'<div class="err">Some steps failed — see details.</div>');
  $("#rsLog").innerHTML=hd+lns+cloneWarnings(r.warnings);
  if(!r.dry && r.ok){
    // Terminé: plus de bouton de lancement, seule la vérification reste (pied de la fenêtre).
    rsFinish(state.cloneNsMode==="other" ? $("#rsCloneTargetNs").value.trim(): $("#rsNs").value,
             false, sess, !!cloneWarnings(r.warnings));
  }
}
// Étape 2 -> lancement direct: une seule confirmation, clones HYCU si nécessaire, puis la copie.
async function cloneAppDirect(){
  $("#rsErr").innerHTML="";
  const items=collectItems();
  if(!items.length && !rsStatelessClone()){ $("#rsErr").innerHTML='<div class="err">Tick at least one PVC.</div>'; return; }
  if(state.cloneNsMode==="other" && !$("#rsCloneTargetNs").value.trim()){ $("#rsErr").innerHTML='<div class="err">Provide the target namespace.</div>'; return; }
  if(dry()){ $("#rsPreview").click(); return; }          // simulation: aperçu, rien n'est créé
  const batch=$("#hyBatchGo");
  const pending = !rsStatelessClone() && !!batch && !(items.length && items.every(refOk));
  const res=await confirmCloneApp(pending);
  if(!res) return;
  const confirmedCtx = (typeof res==="string") ? res: "";
  cloneBusy=true; rsWizSync();
  try{
    if(pending){
      const ok=await hyBatchRun({skipConfirm:true, noChain:true});
      if(!ok) return;                                      // erreurs affichées volume par volume
    }
    $("#rsRepl").innerHTML=""; $("#rsSteps").innerHTML=""; $("#rsLog").innerHTML="";
    state.preview={_cloneapp:true};          // “Relancer” depuis cette page = la copie, jamais la restauration destructive
    $("#rsPlan").style.display="block"; rsShowPage("plan");
    await runCloneApp(confirmedCtx);
  } finally { cloneBusy=false; rsWizSync(); }
}
$("#rsGo").onclick=async()=>{
  hideNextBar();   // pas de “prochaine action” pendant l'exécution
  const live=!dry();
  if(state.preview && state.preview._cloneapp){
    let confirmedCtxCA="";
    if(live){
      const res = await confirmCloneApp(false);
      if(!res) return;
      if(typeof res==="string") confirmedCtxCA=res;
    }
    await runCloneApp(confirmedCtxCA);
    return;
  }
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res = await confirmDanger({title:"Confirm the restore", requireText:needCtx, lines:[
      "Namespace: <b>"+esc($("#rsNs").value||"?")+"</b>",
      "Target cluster: <b>"+esc(ctxInfo.context||"?")+"</b>",
      "The application will be <b>stopped</b>, the old PVCs/PVs <b>deleted</b> then recreated on the restored Volume Group(s)."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  const b=$("#rsGo"); b.disabled=true; b.innerHTML='<span class="spin"></span>Executing…';
  const sess=rsSession, mine=()=>sess===rsSession;
  const body={...state.preview,dry:dry()};
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx || $("#rsCtxInput").value.trim();
  setRsStep(4); rsRunning=true;
  const total=($("#rsSteps").children.length||1)+8;              // étapes prévues + préflight/réplicas/vérif
  $("#rsProgress").style.display="block"; $("#rsProgressBar").style.width="2%";
  $("#rsProgressTxt").textContent="Starting…"; $("#rsCancel").style.display = live ? "": "none"; $("#rsCancel").disabled=false;
  $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Starting…</div>';
  const r=await runOp("/api/execute_restore", body, log=>{
    const done=log.length, last=log[log.length-1];
    $("#rsProgressBar").style.width=Math.min(96, Math.round(100*done/total))+"%";
    $("#rsProgressTxt").textContent="Step "+done+" · "+((last&&last.label)||"…");
    if(mine()) $("#rsLog").innerHTML='<div class="hint"><span class="spin"></span> Execution in progress…</div>'+renderLog(log); });
  rsRunning=false; if(!mine()) return;
  $("#rsCancel").style.display="none";
  $("#rsProgressBar").style.width="100%"; $("#rsProgressTxt").textContent = r.aborted ? "Interrupted": (r.ok ? "Completed": "Completed with errors");
  b.disabled=false; updateGoButton(true);
  if(r.error && !(r.log&&r.log.length)){$("#rsLog").innerHTML=errBox(r.error)+renderPreflight(r.preflight);return;}
  const lines=renderLog(r.log);
  let head;
  if(r.dry) head='<div class="note">Simulation finished — here is what would be executed.</div>';
  else if(r.aborted) head='<div class="err"><b>Sequence aborted</b> — the application was left stopped to avoid an inconsistent restart. See details.</div>';
  else if(r.ok) head='<div class="note">Restore to the new volumes finished.</div>';
  else head='<div class="err">Some steps failed — see below.</div>';
  let reprot="";
  if(r.reprotect && r.reprotect.length){
    const items=r.reprotect.map(x=>`<li><b>${esc(x.new_pv_name)}</b> <span class="hint">${esc(x.new_volume_handle||'')}</span></li>`).join("");
    reprot=`<div class="warnbox">⚠ <b>HYCU re-protection required.</b> The cloned Volume Group(s) below
       are <b>not yet protected</b> by HYCU (the app's policy pointed at the old VG).
       <ul class="pvc-list" style="margin-top:8px">${items}</ul>
       <button class="btn" id="rsReprotectBtn" style="margin-top:6px">Re-protect now in HYCU</button></div>`;
  }
  $("#rsLog").innerHTML = head + renderPreflight(r.preflight) + lines + reprot;
  const rb=$("#rsReprotectBtn"); if(rb) rb.onclick=()=>goReprotect($("#rsNs").value);
  // Re-protection HYCU à traiter: pas de bascule automatique (le bouton reste dans le journal).
  if(!r.dry && r.ok && !r.aborted) rsFinish($("#rsNs").value, !!reprot, sess);
};

// --------- Vérification ---------
async function runVerify(){
  const ns=$("#vfNs").value;
  const r=await get("/api/verify?ns="+encodeURIComponent(ns));
  if(r.error){
    let html=errBox(r.error);
    // Erreur actionnable: namespace hors liste blanche (ex. namespace créé par un
    // clone AVANT que l'ajout automatique n'existe) -> proposer l'ajout en un clic.
    if(r.ns_not_allowed) html+=`<div style="margin-top:8px"><button class="btn" id="vfAllowNs">Allow “${esc(ns)}” and retry</button></div>`;
    $("#vfOut").innerHTML=html;
    const ab=$("#vfAllowNs");
    if(ab) ab.onclick=async()=>{
      const f=await get("/api/ns_filter");
      const rr=await post("/api/ns_filter",{filter:(f.filter||[]).concat([ns])});
      if(!rr.ok){ $("#vfOut").innerHTML=errBox(rr.error||"Could not update the filter."); return; }
      const n=await get("/api/namespaces");            // recharger les listes déroulantes
      const opts=(n.namespaces||[]).map(x=>`<option>${esc(x)}</option>`).join("");
      ["#bkNs","#rsNs","#vfNs"].forEach(id=>$(id).innerHTML=opts||"<option>—</option>");
      $("#vfNs").value=ns; state.ns=ns; applyGlobalNs();
      runVerify();
    };
    return false;
  }
  const pvcs=r.pvcs.map(p=>`<li class="logline"><span>${badge(p.phase)} <b>${esc(p.name)}</b>
     <span class="hint">→ ${esc(p.pv||'—')}</span></span></li>`).join("")||'<div class="hint">No PVC.</div>';
  let allReady=r.pods.length>0;
  const pods=r.pods.map(p=>{
    const ok=p.phase==="Running"; if(!ok) allReady=false;
    const issue = p.issue ? `<div class="hint" style="color:var(--red);margin-top:3px">⚠ ${esc(p.issue.reason)}${p.issue.count>1?' (×'+p.issue.count+')':''}: ${esc(p.issue.message)}</div>`: "";
    return `<li class="logline"><span class="ic ${ok?'ok':'sim'}">${ok?'✓':'○'}</span>
     <span><b>${esc(p.name)}</b> <span class="hint">${esc(p.phase)}${p.waiting?' · '+esc(p.waiting):''} · ready ${esc(p.ready)}</span>${issue}</span></li>`;}).join("")
     ||'<div class="hint">No pods.</div>';
  $("#vfOut").innerHTML=`<div style="margin-top:12px"><b style="font-size:13px">PVC</b>
     <ul class="pvc-list">${pvcs}</ul><b style="font-size:13px">Pods</b><ul class="pvc-list">${pods}</ul></div>`;
  const allBound=r.pvcs.every(p=>(p.phase||"").toLowerCase()==="bound");
  return allBound && allReady;
}
$("#vfRun").onclick=runVerify;
// Suivi auto CONTINU: rafraîchit toutes les ~3 s jusqu'à l'état stable (tous les PVC
// Bound + pods Running), avec plafond de sécurité ~10 min. Re-cliquer arrête le suivi.
let vfTrack=false, vfSeq=0;
function vfSetBtn(){ $("#vfAuto").textContent = vfTrack? "■ Stop tracking": "Auto-track (until stable)"; }
function vfStop(){ vfSeq++; vfTrack=false; vfSetBtn(); }
async function vfAutoTrack(){
  if(vfTrack){ vfStop(); return; }               // stop demandé: la boucle en cours s'arrête
  const my=++vfSeq; vfTrack=true; vfSetBtn();
  for(let i=0;i<200 && vfTrack && vfSeq===my;i++){   // ~10 min à 3 s; une seule boucle à la fois
    const done=await runVerify();
    if(vfSeq!==my) return;
    if(done){ $("#vfOut").insertAdjacentHTML("afterbegin",'<div class="note">Stable state: all PVCs are Bound and pods are Running.</div>'); break; }
    await sleep(3000);
  }
  if(vfSeq===my){ vfTrack=false; vfSetBtn(); }
}
$("#vfAuto").onclick=vfAutoTrack;
// Ouvre l'onglet Vérifier sur un namespace donné (après une restauration réelle) et
// démarre le suivi. Un namespace fraîchement créé (clone d'app) est ajouté à la liste.
function gotoVerify(ns, track){
  if(ns){
    const sel=$("#vfNs");
    if(sel && ![...sel.options].some(o=>o.value===ns)) sel.insertAdjacentHTML("beforeend",`<option>${esc(ns)}</option>`);
    state.ns=ns;
  }
  switchTab("verify");
  if(track && !vfTrack) vfAutoTrack(); else runVerify();
}

// --------- Réglages ---------
async function loadConfig(){
  const r=await get("/api/config"); const c=r.config||{};
  $("#cfgKubectl").value=c.kubectl_path||""; $("#cfgVhPrefix").value=c.volume_handle_prefix||"";
  $("#cfgCtx").value=(c.allowed_contexts||[]).join(", ");
  $("#cfgNs").value=(c.namespace_filter||[]).join(", ");
  $("#cfgLabelSel").value=c.namespace_label_selector||"";
  $("#cfgAuditDays").value=(c.audit_retention_days??31);
  $("#cfgMinFree").value=(c.storage_min_free_mb??500);
  $("#cfgQuota").value=(c.storage_quota_gb??0);
  $("#cfgDr").checked=!!c.allow_dr_restore;
  $("#cfgHosts").value=(c.allowed_hosts||[]).join(", ");
  $("#cfgWait").value=c.wait_timeout;
  $("#cfgConfirm").checked=!!c.require_context_confirm; $("#cfgStrip").checked=!!c.strip_claimref;
  $("#cfgSim").checked=!!c.simulation_mode_available;
  applySimAvailability(c.simulation_mode_available);
  $("#cfgKubeconfig").value=c.kubeconfig_path||"";
  $("#cfgContext").innerHTML=`<option value="${esc(c.kube_context||'')}">${esc(c.kube_context||'(current kubeconfig context)')}</option>`;
}
$("#ctxList").onclick=async()=>{
  const kc=$("#cfgKubeconfig").value.trim();
  $("#ctxMsg").textContent="…";
  const r=await get("/api/contexts"+(kc?("?kubeconfig="+encodeURIComponent(kc)):""));
  if(!r.ok){ $("#ctxMsg").innerHTML=`<span class="ko">${esc(r.error||'kubectl unavailable')}</span>`; return; }
  const cur=r.selected||"";
  $("#cfgContext").innerHTML=`<option value="">(current kubeconfig context)</option>`+
    (r.contexts||[]).map(c=>`<option value="${esc(c)}" ${c===cur?'selected':''}>${esc(c)}</option>`).join("");
  $("#ctxMsg").textContent=`${(r.contexts||[]).length} context(s) found`;
};
$("#ctxApply").onclick=async()=>{
  const cfg={kube_context:$("#cfgContext").value, kubeconfig_path:$("#cfgKubeconfig").value.trim()};
  const r=await post("/api/config",{config:cfg});
  if(!r.ok){ $("#ctxMsg").innerHTML=`<span class="ko">${esc(r.error||'error')}</span>`; return; }
  $("#ctxMsg").textContent = cfg.kube_context? ("Context “"+cfg.kube_context+"” applied."): "Current context in use.";
  await initApp();   // recharge en-tête + namespaces sur le nouveau cluster
};
function csv(s){return (s||"").split(",").map(x=>x.trim()).filter(Boolean);}
$("#cfgSave").onclick=async()=>{
  const cfg={kubectl_path:$("#cfgKubectl").value.trim()||"kubectl",
    volume_handle_prefix:$("#cfgVhPrefix").value.trim(),
    allowed_contexts:csv($("#cfgCtx").value), namespace_filter:csv($("#cfgNs").value), allowed_hosts:csv($("#cfgHosts").value),
    namespace_label_selector:$("#cfgLabelSel").value.trim(),
    audit_retention_days:Math.max(0,parseInt($("#cfgAuditDays").value)||0),
    storage_min_free_mb:Math.max(0,parseInt($("#cfgMinFree").value)||0),
    storage_quota_gb:Math.max(0,parseInt($("#cfgQuota").value)||0),
    allow_dr_restore:$("#cfgDr").checked,
    wait_timeout:parseInt($("#cfgWait").value)||120,
    require_context_confirm:$("#cfgConfirm").checked, strip_claimref:$("#cfgStrip").checked,
    simulation_mode_available:$("#cfgSim").checked};
  const r=await post("/api/config",{config:cfg});
  $("#cfgMsg").textContent = r.ok? "Saved.": ("Error: "+(r.error||""));
  if(r.ok) applySimAvailability(cfg.simulation_mode_available);   // bandeau simulation affiché/masqué sans rechargement
  ctxInfo=await get("/api/context");
};

// --------- Connexions HYCU / Nutanix ---------
let conn = {hycu:{connected:false}, nutanix:{connected:false}};
function connDot(on){ return `<span class="conn-dot ${on?'on':''}"></span>`; }
async function loadConnStatus(){
  let s = await get("/api/conn_status");
  if(!s || !s.hycu) s = {hycu:{}, nutanix:{}, prismcentral:{}, vault:(s&&s.vault)||{}};  // réponse d'erreur: ne pas casser l'init
  conn = s;
  ntAllVgs=null;   // invalide le cache des VG Nutanix après tout (dé)connexion
  const st=(x)=>connDot(x.connected)+(x.connected?"connected":"not connected");
  $("#hyStatus").innerHTML=st(s.hycu); $("#ntStatus").innerHTML=st(s.nutanix); $("#pcStatus").innerHTML=st(s.prismcentral);
  const s3=s.s3||{};
  $("#s3Status").innerHTML=st(s3);
  if(!$("#s3Url").value) $("#s3Url").value=s3.url||"";
  if(!$("#s3Bucket").value) $("#s3Bucket").value=s3.bucket||"";
  if(!$("#s3Region").value) $("#s3Region").value=s3.region||"";
  $("#s3Tls").checked=!!s3.verify_tls; $("#s3Auto").checked=!!s3.auto_upload;
  $("#s3Enc").checked=!!s3.encrypt; $("#s3EncWrap").style.display=s3.encrypt?"block":"none";
  if(!$("#hyUrl").value) $("#hyUrl").value = s.hycu.url||"";
  if(!$("#ntUrl").value) $("#ntUrl").value = s.nutanix.url||"";
  if(!$("#pcUrl").value) $("#pcUrl").value = s.prismcentral.url||"";
  $("#hyTls").checked=!!s.hycu.verify_tls; $("#ntTls").checked=!!s.nutanix.verify_tls; $("#pcTls").checked=!!s.prismcentral.verify_tls;
  $("#bkProtectOff").style.display = s.hycu.connected? "none":"block";
  $("#bkProtectOn").style.display = s.hycu.connected? "block":"none";
  renderHdrConn();
  loadVaultStatus();
}
// Pastilles d'état permanentes dans l'en-tête: HYCU / Prism Element / Prism Central.
// Un clic ouvre l'onglet Connexions (l'opérateur voit AVANT d'agir s'il est connecté).
function renderHdrConn(){
  $("#hdrConn").innerHTML=[["HYCU",conn.hycu],["PE",conn.nutanix],["PC",conn.prismcentral]]
    .map(([l,x])=>`<span class="hc">${connDot(!!(x&&x.connected))}${l}</span>`).join("");
  renderSourcesTable();
}
function loadVaultStatus(){
  const present = conn && conn.vault && conn.vault.present;
  $("#vaultStatus").innerHTML = connDot(present) + (present? "vault present": "no vault");
  $("#vaultLoad").style.display = present? "inline-block": "none";
  $("#vaultForget").style.display = present? "inline-block": "none";
}
function renderKubeBanner(){
  const el=$("#kubeBanner");
  if(ctxInfo.kubectl_ok){ el.style.display="none"; el.innerHTML=""; return; }
  const tips={
    kubectl_missing:"<b>kubectl not found.</b> Install kubectl and add it to PATH, or set its binary/path in ⚙ Settings (e.g. “microk8s kubectl”).",
    no_context:"<b>No kubectl context selected.</b> Choose the target cluster: <code>kubectl config use-context &lt;name&gt;</code>, then reload the page.",
    no_kubeconfig:"<b>No kubectl configuration found.</b> Check <code>%USERPROFILE%\\.kube\\config</code> (or the <code>KUBECONFIG</code> variable), then reload.",
    other:"<b>Cluster unreachable via kubectl.</b> Check network connectivity and your RBAC rights on the API server."
  };
  const tip=tips[ctxInfo.kubectl_hint]||tips.other;
  el.innerHTML=`<div class="warnbox" style="margin-bottom:14px">⚠ ${tip}
    <div class="hint" style="margin-top:6px">The <b>Back up</b>, <b>Restore</b> (Kubernetes sequence) and <b>Verify</b> operations require kubectl. The <b>HYCU / Nutanix</b> connections work without kubectl.${ctxInfo.error?`<br><code style="color:#7a221b">${esc(ctxInfo.error)}</code>`:''}</div></div>`;
  el.style.display="block";
}
async function vaultAction(url, needPass){
  $("#vaultErr").innerHTML="";
  const body = needPass? {passphrase:$("#vaultPass").value}: {};
  const r = await post(url, body);
  $("#vaultPass").value="";
  return r;
}
$("#vaultSave").onclick=async()=>{
  const r=await vaultAction("/api/creds/save", true);
  $("#vaultErr").innerHTML = r.ok? `<div class="note">Connections encrypted: ${esc((r.saved||[]).join(', ')||"—")}.`+
      ((r.clusters||[]).length?`<br>Kubernetes clusters encrypted: ${esc(r.clusters.join(', '))}.`:"")+`</div>`
                                : errBox(r.error);
  await loadConnStatus();
};
$("#vaultLoad").onclick=async()=>{
  const r=await vaultAction("/api/creds/load", true);
  $("#vaultErr").innerHTML = r.ok? `<div class="note">Connections loaded: ${esc((r.loaded||[]).join(', ')||"—")}.`+
      ((r.clusters||[]).length?`<br>Kubernetes clusters loaded: ${esc(r.clusters.join(', '))}.`:"")+`</div>`
                                : errBox(r.error);
  await loadConnStatus();
  if(r.ok) await afterVaultLoad();
};
$("#vaultForget").onclick=async()=>{
  if(!confirm("Delete the encrypted vault from disk?")) return;
  const r=await vaultAction("/api/creds/forget", false);
  $("#vaultErr").innerHTML = r.ok? '<div class="note">Vault deleted.</div>': `<div class="err">${esc(r.error||'')}</div>`;
  await loadConnStatus();
};
let hyAuthMode="basic";
document.querySelectorAll("#hyAuthMode button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#hyAuthMode button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on"); hyAuthMode=b.dataset.mode;
  $("#hyBasicFields").style.display = hyAuthMode==="basic"?"flex":"none";
  $("#hyApiField").style.display = hyAuthMode==="apikey"?"block":"none";
});
const SYS={
  hycu:        {p:'hy', urlKey:'hycu_url',         tlsKey:'hycu_verify_tls'},
  nutanix:     {p:'nt', urlKey:'nutanix_url',      tlsKey:'nutanix_verify_tls'},
  prismcentral:{p:'pc', urlKey:'prismcentral_url', tlsKey:'prismcentral_verify_tls'},
};
async function connectSystem(sys){
  const m=SYS[sys], P='#'+m.p;
  $(P+'Err').innerHTML="";
  const url=$(P+'Url').value.trim();
  if(!url){ $(P+'Err').innerHTML='<div class="err">Enter the URL.</div>'; return; }
  const cfg={}; cfg[m.urlKey]=url; cfg[m.tlsKey]=$(P+'Tls').checked;
  await post("/api/config",{config:cfg});
  let body={system:sys, auth_mode:'basic'};
  if(sys==='hycu' && hyAuthMode==='apikey'){ body.auth_mode='apikey'; body.api_key=$("#hyApiKey").value; }
  else { body.user=$(P+'User').value.trim(); body.password=$(P+'Pass').value; }
  const r=await post("/api/connect",body);
  $(P+'Pass').value=""; if(sys==='hycu') $("#hyApiKey").value="";
  if(!r.ok){ $(P+'Err').innerHTML=errBox(r.error); }
  else if(r.warning){ $(P+'Err').innerHTML=`<div class="warnbox">${esc(r.warning)}</div>`; }
  await loadConnStatus();
}
async function disconnectSystem(sys){ await post("/api/disconnect",{system:sys}); await loadConnStatus(); }
$("#s3Connect").onclick=async()=>{
  $("#s3Err").innerHTML="";
  const b=$("#s3Connect"); b.disabled=true; b.innerHTML='<span class="spin"></span>Testing bucket…';
  const r=await post("/api/s3/connect",{s3_url:$("#s3Url").value.trim(), s3_bucket:$("#s3Bucket").value.trim(),
    s3_region:$("#s3Region").value.trim()||"us-east-1", s3_verify_tls:$("#s3Tls").checked,
    s3_path_style:$("#s3PathStyle").checked, s3_auto_upload:$("#s3Auto").checked,
    s3_encrypt:$("#s3Enc").checked, enc_passphrase:$("#s3EncPass").value,
    access:$("#s3Access").value.trim(), secret:$("#s3Secret").value});
  $("#s3Secret").value=""; $("#s3EncPass").value=""; b.disabled=false; b.textContent="Test & connect";
  if(!r.ok){ $("#s3Err").innerHTML=errBox(r.error); }
  else { $("#s3Err").innerHTML=`<div class="note">Bucket “${esc(r.bucket||"")}” accessible.`+
    (r.auto_upload?" Automatic export enabled.":" Automatic export disabled (tick the box to enable it).")+`</div>`; }
  await loadConnStatus();
};
$("#s3Enc").onchange=()=>{ $("#s3EncWrap").style.display=$("#s3Enc").checked?"block":"none"; };
function s3ImpSync(){ $("#s3ImportBtn").disabled = !document.querySelectorAll(".s3ImpChk:checked").length; }
$("#s3ListBtn").onclick=async()=>{
  const w=$("#s3ImportWrap");
  if(w.style.display!=="none"){ w.style.display="none"; return; }
  w.style.display="block"; $("#s3ImpRes").innerHTML="";
  $("#s3ListOut").innerHTML='<div class="hint"><span class="spin"></span>Listing bucket…</div>';
  const r=await get("/api/s3/list");
  if(!r.ok){ $("#s3ListOut").innerHTML=errBox(r.error); return; }
  const o=r.objects||[];
  $("#s3ListOut").innerHTML = o.length? `<div class="tcard" style="box-shadow:none;border:1px solid var(--rule)"><table class="ht"><thead><tr><th class="cb"><input type="checkbox" id="s3ImpAll"></th><th>Cluster</th><th>Application</th><th>Timestamp</th><th>Size</th><th>Encrypted</th></tr></thead><tbody>`+
    o.map((x,i)=>`<tr><td class="cb"><input type="checkbox" class="s3ImpChk" data-i="${i}"></td><td>${esc(x.cluster)}</td><td style="color:var(--strong)">${esc(x.namespace)}</td><td>${esc(x.timestamp)}</td><td>${esc(fmtBytes(x.size))}</td><td>${x.encrypted?"yes":"—"}</td></tr>`).join("")+
    `</tbody></table></div>`: '<div class="hint">No tool export in this bucket.</div>';
  window.s3Objs=o;
  document.querySelectorAll(".s3ImpChk").forEach(c=>c.onchange=s3ImpSync);
  const all=$("#s3ImpAll"); if(all) all.onchange=()=>{ document.querySelectorAll(".s3ImpChk").forEach(c=>c.checked=all.checked); s3ImpSync(); };
  s3ImpSync();
};
// ----- Sauvegarde de l'outil (kit: configuration, politiques, coffre chiffré) -----
$("#tkUpload").onclick=async()=>{
  const b=$("#tkUpload"); b.disabled=true;
  const r=await post("/api/tool_kit/upload",{});
  b.disabled=false;
  $("#tkOut").innerHTML = r.ok ? `<div class="note" style="margin-top:8px">Kit exported: <code>${esc(r.key)}</code></div>`: errBox(r.error);
};
$("#tkDownload").onclick=async()=>{
  try{
    const resp=await fetch("/api/tool_kit/download",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF,"X-HYCU-Cluster":ACTIVE_CID},body:"{}"});
    if(!resp.ok) throw new Error("HTTP "+resp.status);
    const blob=await resp.blob(), a=document.createElement("a");
    a.href=URL.createObjectURL(blob); a.download="hycu-tool-"+new Date().toISOString().slice(0,10)+".zip";
    document.body.appendChild(a); a.click(); setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }catch(e){ $("#tkOut").innerHTML=errBox("Download failed: "+(e&&e.message||e)); }
};
$("#tkList").onclick=async()=>{
  $("#tkOut").innerHTML='<div class="hint" style="margin-top:8px"><span class="spin"></span></div>';
  const r=await get("/api/tool_kit/list");
  if(!r.ok){ $("#tkOut").innerHTML=errBox(r.error); return; }
  const k=r.kits||[];
  if(!k.length){ $("#tkOut").innerHTML='<div class="hint" style="margin-top:8px">No tool kit in this bucket.</div>'; return; }
  $("#tkOut").innerHTML=`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule);margin-top:8px"><table class="ht"><thead><tr><th class="cb"></th><th>Kit</th><th>Size</th></tr></thead><tbody>`+
    k.map((x,i)=>`<tr><td class="cb"><input type="radio" name="tkPick" value="${esc(x.key)}" data-enc="${x.encrypted?1:0}" ${i===0?"checked":""}></td><td>${esc(x.name)}</td><td>${esc(fmtBytes(x.size))}</td></tr>`).join("")+
    `</tbody></table></div>
    <div class="row" style="margin-top:8px"><div><label class="fld">Encryption passphrase (.enc kits only)</label><input type="password" id="tkPass" autocomplete="off"></div>
    <div style="flex:none;align-self:flex-end"><button class="btn danger" id="tkRestore" type="button">Restore the tool</button></div></div><div id="tkRes"></div>`;
  $("#tkRestore").onclick=async()=>{
    const pick=document.querySelector('input[name="tkPick"]:checked'); if(!pick) return;
    if(!(await confirmDanger({title:"Restore the tool", lines:[
      "The current configuration (policies, filters, sources) and the vault will be replaced by those of kit <b>"+esc(pick.value.split("/").pop())+"</b>.",
      "A copy of the current state is kept in <code>hycu-backups/_tool_restore_backup/</code>."]}))) return;
    const b=$("#tkRestore"); b.disabled=true;
    const res=await post("/api/tool_kit/restore",{key:pick.value, passphrase:$("#tkPass").value});
    $("#tkPass").value=""; b.disabled=false;
    if(!res.ok){ $("#tkRes").innerHTML=errBox(res.error); return; }
    $("#tkRes").innerHTML=`<div class="note" style="margin-top:8px">Tool restored${res.vault?" — then unlock the vault with your passphrase":""}. Reloading…</div>`;
    setTimeout(()=>location.reload(), 1800);
  };
};
$("#s3ImportBtn").onclick=async()=>{
  const items=[...document.querySelectorAll(".s3ImpChk:checked")].map(c=>({key:(window.s3Objs||[])[+c.dataset.i].key}));
  if(!items.length) return;
  const b=$("#s3ImportBtn"); b.disabled=true; b.innerHTML='<span class="spin"></span>Import…';
  const r=await post("/api/s3/import",{items, enc_passphrase:$("#s3ImpPass").value});
  $("#s3ImpPass").value=""; b.disabled=false; b.textContent="Import selection"; s3ImpSync();
  const res=r.results||[];
  $("#s3ImpRes").innerHTML=(r.error&&!res.length?errBox(r.error):"")+(res.length?`<ul class="dlist" style="margin-top:10px">`+res.map(x=>
    `<li><span class="k" style="display:flex;gap:10px;align-items:center">${stIc(x.ok?"ok":"ko")}${esc(x.key)}</span>`+
    `<span class="v" style="font-weight:400">${x.ok? x.files+" file(s)": esc(x.error||"")}</span></li>`).join("")+"</ul>":"");
};
$("#s3Disconnect").onclick=async()=>{ await post("/api/disconnect",{system:"s3"}); $("#s3Err").innerHTML=""; await loadConnStatus(); };
$("#hyConnect").onclick=()=>connectSystem("hycu");
$("#ntConnect").onclick=()=>connectSystem("nutanix");
$("#pcConnect").onclick=()=>connectSystem("prismcentral");
$("#hyDisconnect").onclick=()=>disconnectSystem("hycu");
$("#ntDisconnect").onclick=()=>disconnectSystem("nutanix");
$("#pcDisconnect").onclick=()=>disconnectSystem("prismcentral");

// Nutanix: recherche instantanée d'un VG et remplissage de sa RÉFÉRENCE (VG UUID).
// Les VG sont chargés une fois (pagination serveur) puis filtrés côté navigateur.
let ntAllVgs=null;
async function ntFindRef(pvc){
  const box=document.querySelector(`.ntpick[data-pvc="${CSS.escape(pvc)}"]`);
  if(box.dataset.open==="1"){ box.dataset.open=""; box.innerHTML=""; return; }  // 2e clic = refermer
  box.dataset.open="1";
  box.innerHTML='<div class="hint">Loading Volume Groups…</div>';
  if(ntAllVgs===null){
    const r=await get("/api/nutanix/vgs");
    if(!r.ok){ box.innerHTML=errBox(r.error); return; }
    ntAllVgs=r.vgs||[];
  }
  box.innerHTML=`<div style="border:1px solid var(--line);border-radius:8px;padding:8px;margin-top:6px;background:#fff">
    <input type="text" class="ntSearch" placeholder="search the cloned VG by name…">
    <div class="ntResults" style="max-height:200px;overflow:auto;margin-top:6px"></div>
    <div class="hint ntCount" style="margin-top:4px"></div></div>`;
  const inp=box.querySelector(".ntSearch"), res=box.querySelector(".ntResults"), cnt=box.querySelector(".ntCount");
  function render(){
    const t=(inp.value||"").toLowerCase();
    let list=t? ntAllVgs.filter(v=>(v.name||"").toLowerCase().includes(t)): ntAllVgs;
    const total=list.length, capped=list.length>200; list=list.slice(0,200);
    res.innerHTML=list.length? list.map(v=>`<div class="logline ntRow" data-uuid="${esc(v.uuid)}" style="cursor:pointer">
       <span><b>${esc(v.name||v.uuid)}</b> <span class="hint">UUID ${esc(v.uuid||'?')}</span></span></div>`).join("")
      : '<div class="hint">No Volume Group matches.</div>';
    cnt.textContent=`${total} VG${total>1?'s':''} of ${ntAllVgs.length}`+(capped?' (200 shown — refine the search)':'');
    res.querySelectorAll(".ntRow").forEach(row=>row.onclick=()=>{
      // NKP moderne: l'VG UUID suffit (= suffixe du volumeHandle). Pas d'appel IQN.
      const ref=row.dataset.uuid;
      if(!ref){ box.innerHTML='<div class="err">VG UUID unavailable.</div>'; box.dataset.open=""; return; }
      const ta=document.querySelector(`.rsRef[data-pvc="${CSS.escape(pvc)}"]`); if(ta) ta.value=ref;
      box.innerHTML='<div class="note" style="margin-top:6px">VG reference (UUID) filled from Nutanix.</div>'; box.dataset.open="";
    });
  }
  inp.oninput=render; render(); inp.focus();
}

// Suivi générique d'un job HYCU: barre de progression + polling (backup ou restore).
async function pollJobBar(id, target){
  const el=(typeof target==="string")?$(target):target; if(!el) return false;
  let errs=0;
  for(let i=0;i<240;i++){                       // ~12 min max (240 * 3s)
    const r=await post("/api/hycu/job",{job_id:id});
    if(!r.ok){
      if((r.http_status===0 || r.http_status>=500) && ++errs<=10){     // coupure passagère: on réessaie
        el.innerHTML=`<div class="hint">Job tracking: retrying (${errs}/10)…</div>`;
        await new Promise(s=>setTimeout(s,3000)); continue;
      }
      el.innerHTML=`<div class="hint">Job tracking unavailable: ${esc(r.error||'')}</div>`; return false; }
    errs=0;
    const pct=(r.progress!=null)?r.progress:0, status=r.status||"?";
    el.innerHTML=`<div class="hint" style="margin-top:8px">Job <code>${esc(id)}</code> — ${esc(status)}${r.progress!=null?(' · '+pct+'%'):''}</div>
       <div class="jbar"><span style="width:${pct}%"></span></div>`;
    if(/^(OK|DONE|SUCCESS|SUCCEEDED|COMPLETED?|FINISHED|WARNING)$/i.test(status)){ el.innerHTML+='<div class="note" style="margin-top:6px">Job finished successfully.</div>'; return true; }
    if(/^(FAILED|ERROR|FATAL|ABORTED?|CANCEL+ED|TIMEOUT)$/i.test(status)){ el.innerHTML+='<div class="err" style="margin-top:6px">Job failed — check in HYCU.</div>'; return false; }
    await new Promise(s=>setTimeout(s,3000));
  }
  el.innerHTML+='<div class="hint">Tracking stopped (timeout) — the job continues on the HYCU side.</div>';
  return false;
}

// --------- Filtre des namespaces (éditeur) ---------
async function refreshNamespaces(){
  if(typeof clearBkProtect==="function") clearBkProtect();   // l'analyse HYCU précédente n'est plus valide
  const n=await get("/api/namespaces"); const list=n.namespaces||[];
  const opts=list.map(x=>`<option>${esc(x)}</option>`).join("");
  ["#bkNs","#rsNs","#vfNs"].forEach(id=>{
    const cur=$(id).value; $(id).innerHTML=opts||"<option>—</option>";
    if(cur && list.includes(cur)){ $(id).value=cur; return; }
    // La namespace sélectionnée a disparu du nouveau filtre -> purge de l'état dépendant.
    if(id==="#bkNs"){ $("#bkOut").innerHTML=""; }
    else if(id==="#vfNs"){ $("#vfOut").innerHTML=""; }
    else if(id==="#rsNs"){ $("#rsConfig").style.display="none"; $("#rsPlan").style.display="none";
      $("#rsLog").innerHTML=""; $("#rsErr").innerHTML=""; state.preview=null; loadPvcs(); }
  });
}
let nsAllList=[], nsChecked=new Set();
function nsVisible(){ const t=($("#nsSearch").value||"").toLowerCase(); return nsAllList.filter(x=>!t||x.toLowerCase().includes(t)); }
function nsTogglePick(){ const off=$("#nsAll").checked; $("#nsPick").style.opacity=off?".45":"1"; $("#nsPick").style.pointerEvents=off?"none":"auto"; }
function nsUpdateCount(){
  if($("#nsAll").checked){ $("#nsCount").textContent="all"; return; }
  const allManual = nsAllList.length>0 && nsChecked.size===nsAllList.length;
  $("#nsCount").textContent = nsChecked.size+" / "+nsAllList.length+" selected"
    + (allManual? " · future namespaces excluded (tick “All”)": "");
}
function renderNsList(){
  const vis=nsVisible();
  $("#nsList").innerHTML = vis.length? ('<ul class="pvc-list" style="margin:0">'+vis.map(n=>`<li><label style="display:flex;gap:10px;align-items:center;cursor:pointer;width:100%">
      <input type="checkbox" class="nsChk" value="${esc(n)}" ${nsChecked.has(n)?'checked':''} style="width:auto">
      <span class="nm">${esc(n)}</span></label></li>`).join("")+'</ul>')
   : '<div class="hint">No namespace matches.</div>';
  $("#nsList").querySelectorAll(".nsChk").forEach(c=>c.onchange=()=>{ c.checked? nsChecked.add(c.value):nsChecked.delete(c.value); nsUpdateCount(); });
  nsUpdateCount();
}
async function openNsFilter(){
  // Normalisation systématique: on repart d'un état propre à chaque ouverture,
  // et la sauvegarde reste désactivée tant que le filtre réel n'est pas chargé
  // (sinon, kubectl en panne -> on enregistrerait [] = écrasement de la whitelist).
  $("#nsFilterErr").innerHTML=""; $("#nsAll").checked=false;
  nsAllList=[]; nsChecked=new Set(); $("#nsSearch").value="";
  $("#nsSave").disabled=true;
  nsTogglePick(); renderNsList();
  $("#nsFilter").style.display="flex";
  const r=await get("/api/ns_filter");
  if(!r.ok){ $("#nsFilterErr").innerHTML=`<div class="err">${esc(r.error||'kubectl unavailable')} — could not load the list; saving disabled.</div>`; return; }
  nsAllList=r.all||[]; const filt=r.filter||[], noFilter=filt.length===0;
  $("#nsAll").checked=noFilter;
  nsChecked=new Set(noFilter? nsAllList: filt);
  $("#nsSave").disabled=false;
  nsTogglePick(); renderNsList();
}
document.querySelectorAll(".nsEdit").forEach(b=>b.onclick=openNsFilter);
$("#nsAll").onchange=()=>{ nsTogglePick(); nsUpdateCount(); };
$("#nsSearch").oninput=renderNsList;
$("#nsCheckAll").onclick=()=>{ nsVisible().forEach(n=>nsChecked.add(n)); renderNsList(); };
$("#nsUncheckAll").onclick=()=>{ nsVisible().forEach(n=>nsChecked.delete(n)); renderNsList(); };
$("#nsCancel").onclick=()=>{ $("#nsFilter").style.display="none"; };
$("#nsSave").onclick=async()=>{
  const filter = $("#nsAll").checked? []: [...nsChecked];
  const r=await post("/api/ns_filter",{filter});
  if(!r.ok){ $("#nsFilterErr").innerHTML=`<div class="err">${esc(r.error||'error')}</div>`; return; }
  $("#nsFilter").style.display="none";
  await refreshNamespaces();
  $("#cfgNs").value=(r.filter||[]).join(", ");   // garder l'onglet Réglages cohérent
  onPageShown(curPage);                          // Applications / tableau de bord à jour
};
refreshDry();

// ============================================================================
// Interface “HYCU Enterprise Cloud”: pages (Tableau de bord, Applications,
// Politiques, Tâches) et modales d'opération (Sauvegarde, Set Policy,
// Restauration, Sources). Les blocs d'origine (mêmes IDs, même logique testée)
// sont hébergés dans ces modales: ce code se contente de les piloter.
// ============================================================================
var rsAutoCheck=false;            // assistant ouvert: volumes présélectionnés (cf. renderRsPvcs)
var pageTimer=null;
const MODALS=["mBackup","mPolicy","mRestore","mSources","mBulk","mPurge"];
const FOCUSABLE='a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
let modalReturnFocus={};
function openModal(id){
  const m=$("#"+id); if(!m) return;
  const box=m.querySelector(".hmodal")||m;
  box.setAttribute("role","dialog"); box.setAttribute("aria-modal","true");
  const h=box.querySelector("h2,h3"); if(h){ if(!h.id) h.id=id+"-title"; box.setAttribute("aria-labelledby",h.id); }
  modalReturnFocus[id]=document.activeElement;
  m.style.display="flex";
  const first=box.querySelector(FOCUSABLE); if(first) setTimeout(()=>first.focus(),30);
}
function closeModal(id){
  const m=$("#"+id); if(!m || m.style.display==="none") return;
  if(id==="mRestore" && rsRunning){
    $("#rsLog").insertAdjacentHTML("afterbegin",'<div class="warnbox">Operation in progress: it keeps running server-side. You can resume tracking from the banner at the top of the page.</div>');
  }
  m.style.display="none";
  if(id==="mRestore") rsAutoCheck=false;
  if(id==="mSources"){ const k=$("#clKc"); if(k) k.value=""; const n=$("#clName"); if(n) n.value=""; }   // kubeconfig = secret
  const rf=modalReturnFocus[id]; if(rf && rf.focus) try{ rf.focus(); }catch(e){}
  if(id!=="mSources") onPageShown(curPage);        // l'opération a pu changer l'état affiché
}
// Piège de focus: Tab reste dans la modale ouverte la plus haute.
document.addEventListener("keydown", e=>{
  if(e.key!=="Tab") return;
  const open=MODALS.map(id=>$("#"+id)).filter(m=>m && m.style.display!=="none");
  const m=open[open.length-1]; if(!m) return;
  const f=[...m.querySelectorAll(FOCUSABLE)].filter(el=>el.offsetParent!==null); if(!f.length) return;
  if(e.shiftKey && document.activeElement===f[0]){ e.preventDefault(); f[f.length-1].focus(); }
  else if(!e.shiftKey && document.activeElement===f[f.length-1]){ e.preventDefault(); f[0].focus(); }
});
function closeAllModals(){ MODALS.forEach(closeModal); }
document.querySelectorAll("[data-close]").forEach(b=>b.onclick=()=>closeModal(b.dataset.close));
document.addEventListener("keydown",e=>{
  if(e.key!=="Escape") return;
  if($("#dangerModal").style.display!=="none" || $("#nsFilter").style.display!=="none") return;
  const open=MODALS.filter(id=>$("#"+id).style.display!=="none");
  if(open.length) closeModal(open[open.length-1]);
});
function bindGo(root){ (root||document).querySelectorAll("[data-go]").forEach(a=>a.onclick=e=>{ e.preventDefault(); switchTab(a.dataset.go); }); }
bindGo();

// ----- Barre du haut / barre latérale -----
// Engrenage: petit menu (Sources / Réglages), même style que le menu des clusters.
function toggleGearMenu(){
  const m=$("#gearMenu");
  if(m.style.display==="block"){ m.style.display="none"; return; }
  $("#clMenu").style.display="none"; $("#helpMenu").style.display="none";
  const r=$("#srcBtn").getBoundingClientRect();
  m.style.right=Math.max(8, window.innerWidth-r.right-10)+"px";
  m.style.display="block";
}
$("#srcBtn").onclick=e=>{ e.stopPropagation(); toggleGearMenu(); };
document.querySelectorAll("#gearMenu .cli").forEach(el=>el.onclick=e=>{
  e.stopPropagation(); $("#gearMenu").style.display="none";
  if(el.dataset.act==="sources") openSources();
  else switchTab("settings");
});
$("#ctxLink").onclick=e=>{ e.stopPropagation(); toggleClMenu(); };
$("#tbHome").onclick=e=>{ e.preventDefault(); switchTab("dashboard"); };
$("#sbCol").onclick=()=>{ const m=!document.body.classList.contains("sb-min");
  document.body.classList.toggle("sb-min",m); savePref("sbMin",m); };
if(prefs().sbMin) document.body.classList.add("sb-min");

// ----- Petits formats -----
const AGO={now:"just now", min:"%d min ago", h:"%d h ago", d:"%d d ago"};
function fmtAgo(ts){
  if(!ts) return "";
  const s=Math.max(0, Date.now()/1000-ts);
  if(s<60) return AGO.now;
  if(s<3600) return AGO.min.replace("%d", Math.round(s/60));
  if(s<86400) return AGO.h.replace("%d", Math.round(s/3600));
  return AGO.d.replace("%d", Math.round(s/86400));
}
let DATE_FMT=null;   // créé à la première utilisation
function fmtTs(iso){
  if(!iso) return "—"; const d=new Date(iso); if(isNaN(d)) return String(iso);
  if(!DATE_FMT) DATE_FMT=new Intl.DateTimeFormat("en-GB", {dateStyle:"short", timeStyle:"medium"});
  return DATE_FMT.format(d);
}
const ST_LABEL={ok:"OK", ko:"Failed", wn:"Warning", na:"Unknown", sim:"Simulation", run:"Running"};
function stIc(kind, title){
  const g={ok:"✓", ko:"✕", wn:"!", na:"?", sim:"○", run:"▸"}[kind]||"?";
  const lab=title||ST_LABEL[kind]||"";
  return `<span class="st ${kind}" role="img" aria-label="${esc(lab)}" title="${esc(lab)}">${g}</span>`;
}
function dnums(l1, v1, l2, v2){
  return `<div class="dnums"><div><div class="l">${l1}</div><div class="v">${v1}</div></div>`+
         `<div><div class="l">${l2}</div><div class="v">${v2}</div></div></div>`;
}
// Anneaux “à la HYCU”: extérieur (épais) = première mesure, intérieur (fin) = seconde.
function donutSVG(outer, inner){
  const clamp=v=>Math.max(0, Math.min(100, v||0));
  const R1=62, R2=47, C1=2*Math.PI*R1, C2=2*Math.PI*R2, o=clamp(outer), i=clamp(inner);
  return `<svg class="donut" width="164" height="164" viewBox="0 0 164 164" aria-hidden="true">
    <circle cx="82" cy="82" r="76" fill="none" stroke="#9BDAC7" stroke-width="5"/>
    <circle cx="82" cy="82" r="${R1}" fill="none" stroke="#F6D3D1" stroke-width="15"/>
    <circle cx="82" cy="82" r="${R1}" fill="none" stroke="#05A274" stroke-width="15"
            stroke-dasharray="${(C1*o/100).toFixed(1)} ${C1.toFixed(1)}" transform="rotate(-90 82 82)"/>
    <circle cx="82" cy="82" r="${R2}" fill="none" stroke="#EEF0F5" stroke-width="5"/>
    <circle cx="82" cy="82" r="${R2}" fill="none" stroke="#9BDAC7" stroke-width="5"
            stroke-dasharray="${(C2*i/100).toFixed(1)} ${C2.toFixed(1)}" transform="rotate(-90 82 82)"/>
  </svg>`;
}

// ----- Pages: chargement des données à l'affichage (+ rafraîchissement) -----
function onPageShown(tab){
  clearInterval(pageTimer); pageTimer=null;
  const every=(fn, ms)=>{ pageTimer=setInterval(()=>{ if(document.visibilityState==="visible") fn(); }, ms); };
  if(tab==="dashboard"){ loadDashboard(); every(loadDashboard, 30000); }
  else if(tab==="apps") loadApps();
  else if(tab==="jobs"){ loadJobs(); every(loadJobs, 5000); }
  else if(tab==="policies") loadPolicies();
}

// ============================ Applications ============================
let apps=[], appsSel=new Set(), appsFresh=24, appsPolicy={}, appsScope="one", appsClErr=[];
// Clé de sélection = cluster|namespace (vue “All clusters”: un même nom de
// namespace peut exister sur plusieurs clusters).
// Clé d'une ligne: cluster | namespace | application (plusieurs applications par namespace).
const appKey=a=>(a.cluster_id||ACTIVE_CID)+"|"+(a.namespace||a.name)+"|"+a.name;
const appNs=a=>a.namespace||a.name;
// Libellé du type d'application (stateful = monte des volumes; stateless = configuration seule).
function appTypeCell(a){
  if(a.missing) return '<span class="badge b-lost">Deleted — restorable</span>'+(a.type==="stateless"?' <span class="hint">stateless</span>':"");
  if(a.type==="stateful") return '<span class="badge b-bound">Stateful</span> <span class="hint">'+(a.volumes||0)+' volume(s)</span>'+(a.unassigned?' <span class="hint">· no workload</span>':"");
  if(a.type==="stateless") return '<span class="badge b-pending">Stateless</span> <span class="hint">'+((a.workloads||[]).length)+' workload(s)</span>';
  if(a.type==="empty") return '<span class="badge b-na">Empty</span>';
  return '<span class="badge b-na">Namespace</span>';
}
function updateScopeSeg(){
  const multi=CLUSTERS.length>1;
  $("#appsScope").style.display = multi ? "": "none";
  if(!multi) appsScope="one";
  else if(prefs().appsScope==="all") appsScope="all";
  document.querySelectorAll("#appsScope button").forEach(b=>b.classList.toggle("on", b.dataset.scope===appsScope));
}
document.querySelectorAll("#appsScope button").forEach(b=>b.onclick=()=>{
  appsScope=b.dataset.scope; savePref("appsScope", appsScope); appsSel.clear();
  document.querySelectorAll("#appsScope button").forEach(x=>x.classList.toggle("on", x===b));
  loadApps();
});
// `fresh` (bouton Actualiser): ignore le cache serveur de l'inventaire (apps_cache_ttl_s).
async function loadApps(fresh){
  $("#appsRefresh").classList.add("busy");
  const all = appsScope==="all";
  const r=await get("/api/applications?"+(all ? "scope=all": "scope=one")+(fresh ? "&fresh=1": ""));
  $("#appsRefresh").classList.remove("busy");
  apps=(r.apps||[]).map(a=>all ? a: Object.assign({}, a, {cluster_id:ACTIVE_CID}));
  appsFresh=r.freshness_hours||24; appsPolicy=r.policy||{};
  appsClErr = all ? (r.clusters||[]).filter(c=>!c.ok && !c.skipped): [];
  if(all) apps.sort((x,y)=>(x.workspace||"").localeCompare(y.workspace||"") || (x.cluster||"").localeCompare(y.cluster||"") || appNs(x).localeCompare(appNs(y)) || x.name.localeCompare(y.name));
  const keys=new Set(apps.map(appKey));
  [...appsSel].forEach(k=>{ if(!keys.has(k)) appsSel.delete(k); });
  $("#appsTable").classList.toggle("multi", all);
  if(!r.ok && !apps.length){
    $("#appsBody").innerHTML=`<tr><td colspan="11">${errBox(r.error||"kubectl ?")}</td></tr>`;
    updateAppActs(); return r;
  }
  renderApps(); return r;
}
function appPolicyLabel(a){
  const p=(a && a.policy) || null;
  if(p && p.name) return p.name+" · "+(p.enabled ? (+p.interval_hours)+" h": "paused");
  const d = p || appsPolicy;
  return d.enabled ? ("Automatic configuration · "+Math.round(d.interval_hours||24)+" h"): "None";
}
function appsVisible(){
  const q=($("#appsSearch").value||"").trim().toLowerCase();
  const hideDel=$("#appsHideDel").checked;
  return apps.filter(a=>!(hideDel && a.missing) && (!q || a.name.toLowerCase().includes(q) || appNs(a).toLowerCase().includes(q)
                           || (a.cluster||"").toLowerCase().includes(q) || (a.workspace||"").toLowerCase().includes(q)));
}
// Pagination: au-delà de APPS_PAGE_SIZE lignes (grands clusters), le tableau est
// découpé en pages; la recherche s'applique à toutes les lignes, la sélection persiste.
const APPS_PAGE_SIZE=100; let appsPage=0;
function appsPageRows(rows){
  const nPages=Math.max(1, Math.ceil(rows.length/APPS_PAGE_SIZE));
  if(appsPage>=nPages) appsPage=nPages-1;
  const pg=$("#appsPager");
  if(rows.length<=APPS_PAGE_SIZE){ pg.style.display="none"; pg.innerHTML=""; return rows; }
  const from=appsPage*APPS_PAGE_SIZE, to=Math.min(rows.length, from+APPS_PAGE_SIZE);
  pg.style.display="";
  pg.innerHTML=`<button class="pact" type="button" id="appsPrev" ${appsPage===0?"disabled":""} title="Previous page">‹</button> `+
    `<span>${from+1}–${to} / ${rows.length}</span> `+
    `<button class="pact" type="button" id="appsNext" ${appsPage>=nPages-1?"disabled":""} title="Next page">›</button>`;
  $("#appsPrev").onclick=()=>{ appsPage--; renderApps(); };
  $("#appsNext").onclick=()=>{ appsPage++; renderApps(); };
  return rows.slice(from, to);
}
function renderApps(){
  const rowsAll=appsVisible(), all=appsScope==="all";
  const nNs=new Set(rowsAll.map(a=>(a.cluster_id||"")+"|"+appNs(a))).size;
  $("#appsInfo").textContent=rowsAll.length+" application(s) · "+nNs+" namespace(s)";
  const rows=appsPageRows(rowsAll);
  let h="";
  appsClErr.forEach(c=>{ h+=`<tr class="grp"><td colspan="11">${c.workspace?esc(c.workspace)+'<span class="gs">›</span>':""}${esc(c.cluster)}`+
                             `<span class="ge">${stIc("ko")} ${esc(c.error||"unreachable")}</span></td></tr>`; });
  if(!rows.length){
    h+=`<tr><td colspan="11" class="tempty">${apps.length
      ? "No application matches the search."
     : "No namespace to display — check the kubectl context or the namespace filter."}</td></tr>`;
  } else {
    let grp=null;
    h+=rows.map(a=>{
      let g="";
      const gk=(a.workspace||"")+"|"+(a.cluster_id||"");
      if(all && gk!==grp){ grp=gk;
        g=`<tr class="grp"><td colspan="11">${a.workspace?esc(a.workspace)+'<span class="gs">›</span>':""}${esc(a.cluster||"")}`+
          `${a.cluster_id===ACTIVE_CID?'<span class="tag">ACTIVE</span>':''}</td></tr>`; }
      const k=appKey(a), sel=appsSel.has(k);
      const comp = a.missing ? stIc("na","Namespace deleted from the cluster")
                : a.compliant ? stIc("ok","Recent configuration backup")
                : (a.protected ? stIc("ko","Last backup older than its policy interval")
                               : stIc("na","Never backed up"));
      // Protection = sauvegardes du NAMESPACE; un volume de l'application absent de la
      // dernière sauvegarde (PVC créé depuis) rend sa protection incomplète.
      const unb=(a.unbacked_pvcs||[]);
      const prot = !a.protected ? stIc("na","No configuration backup")
                : (unb.length && !a.missing) ? stIc("wn", "Volume(s) missing from the latest backup: "+unb.join(", ")+" — run a backup again")
                : stIc("ok", a.backups+" configuration backup(s) of the namespace");
      const last = a.last_backup ? esc(fmtAgo(a.last_backup)): '<span style="color:var(--muted)">Never</span>';
      const nameCell = (a.unassigned ? '<i>'+esc(a.name)+'</i>': esc(a.name))
        + (a.whole_ns && !a.missing && a.type!=="empty" ? ' <span class="hint">(whole namespace)</span>': '');
      return g+`<tr class="clk${sel?' sel':''}" data-k="${esc(k)}"${a.missing?' style="opacity:.75"':''}>
        <td class="cb"><input type="checkbox" tabindex="-1" ${sel?"checked":""}></td>
        <td style="color:var(--strong);font-weight:500">${nameCell}</td><td>${esc(appNs(a))}</td>
        <td class="mc">${esc(a.workspace||"—")}</td><td class="mc">${esc(a.cluster||"")}</td>
        <td>${appTypeCell(a)}</td><td>${esc(appPolicyLabel(a))}</td>
        <td class="ctr">${comp}</td><td class="ctr">${prot}</td><td>${last}</td>
        <td class="ctr">${a.backups||0}</td></tr>`;
    }).join("");
  }
  $("#appsBody").innerHTML=h;
  // Sélection: on met à jour LA ligne cliquée (pas de reconstruction du tableau —
  // coûteuse à 1 000 lignes), puis les actions et la case “tout”.
  document.querySelectorAll("#appsBody tr.clk").forEach(tr=>tr.onclick=()=>{
    const k=tr.dataset.k, on=!appsSel.has(k);
    on ? appsSel.add(k): appsSel.delete(k);
    tr.classList.toggle("sel", on); const c=tr.querySelector('input[type="checkbox"]'); if(c) c.checked=on;
    $("#appsAll").checked = rows.length>0 && rows.every(a=>appsSel.has(appKey(a)));
    updateAppActs(); });
  $("#appsAll").checked = rows.length>0 && rows.every(a=>appsSel.has(appKey(a)));
  updateAppActs();
}
function selAppObjs(){ return apps.filter(a=>appsSel.has(appKey(a))); }
// Namespaces distincts de la sélection (la sauvegarde est par namespace: deux
// applications du même namespace = une seule sauvegarde).
function selNsObjs(){
  const seen=new Set(), out=[];
  selAppObjs().forEach(a=>{ const k=(a.cluster_id||ACTIVE_CID)+"|"+appNs(a); if(seen.has(k)) return; seen.add(k);
    out.push({name:appNs(a), cluster_id:a.cluster_id, cluster:a.cluster, workspace:a.workspace, missing:a.missing}); });
  return out;
}
function selApps(){ return selNsObjs().map(a=>a.name); }
function updateAppActs(){
  const objs=selAppObjs(), n=objs.length, anyMissing=objs.some(a=>a.missing), anyEmpty=objs.some(a=>a.type==="empty");
  $("#actBackup").disabled = !n || anyMissing || anyEmpty;
  $("#actVerify").disabled = n!==1 || anyMissing;
  // Purger: les versions d'UN namespace (une ou plusieurs applications de ce namespace).
  $("#actPurge").disabled = !(n>=1 && new Set(objs.map(a=>(a.cluster_id||ACTIVE_CID)+"|"+appNs(a))).size===1 && objs.some(a=>a.backups));
  // Set Policy: une ou PLUSIEURS applications (du même cluster) en une fois.
  const oneCluster = n>=1 && new Set(objs.map(a=>a.cluster_id||ACTIVE_CID)).size===1;
  $("#actPolicy").disabled = !oneCluster || anyMissing || anyEmpty;
  // Restaurer: une application, OU plusieurs applications du MÊME namespace (= tout le
  // namespace, ex. mariadb + wordpress séparés par leurs étiquettes). Un namespace vide
  // reste restaurable s'il a des sauvegardes (application supprimée mais namespace
  // conservé) — restaurer une app SUPPRIMÉE est le cas clé.
  const sameNs = n>=1 && new Set(objs.map(a=>(a.cluster_id||ACTIVE_CID)+"|"+appNs(a))).size===1;
  $("#actRestore").disabled = !sameNs || (anyEmpty && !objs[0].protected);
  const rs=$("#actRestore span"); if(rs){ if(!rs.dataset.lbl) rs.dataset.lbl=rs.textContent;
    rs.textContent = (sameNs && n>1) ? "Restore the namespace": rs.dataset.lbl; }
}
// Opération sur UNE application d'un autre cluster (vue “All clusters”): on
// bascule d'abord le cluster actif, pour que confirmations et garde-fous le désignent.
async function ensureCluster(a){ if(a && a.cluster_id && a.cluster_id!==ACTIVE_CID) await setActiveCluster(a.cluster_id); }
$("#appsSearch").oninput=()=>{ appsPage=0; renderApps(); };
$("#appsHideDel").checked=!!prefs().hideDeleted;
$("#appsHideDel").onchange=()=>{ savePref("hideDeleted", $("#appsHideDel").checked); appsPage=0; renderApps(); };
// “Tout sélectionner” porte sur la PAGE affichée (jamais 1 000 lignes d'un coup à l'insu de l'opérateur).
$("#appsAll").onchange=()=>{ const on=$("#appsAll").checked;
  appsVisible().slice(appsPage*APPS_PAGE_SIZE, (appsPage+1)*APPS_PAGE_SIZE).forEach(a=>on ? appsSel.add(appKey(a)): appsSel.delete(appKey(a))); renderApps(); };
$("#appsRefresh").onclick=()=>loadApps(true);
$("#actBackup").onclick=async()=>{
  const objs=selNsObjs();
  const cids=[...new Set(objs.map(a=>a.cluster_id))];
  if(cids.length===1) await ensureCluster(objs[0]);
  openBackupModal(objs.map(a=>a.name), objs);
};
$("#actRestore").onclick=async()=>{ const objs=selAppObjs(), a=objs[0]; await ensureCluster(a);
  if(a.missing) return openRecoverModal(appNs(a));
  // Plusieurs applications du même namespace sélectionnées -> tout le namespace.
  openRestoreModal(appNs(a), objs.length>1 ? null: a); };
$("#actPolicy").onclick=async()=>{ const objs=selNsObjs(); await ensureCluster(objs[0]); openPolicyModal(objs.length>1 ? objs.map(a=>a.name): appNs(selAppObjs()[0])); };
// ----- Purge des versions de configuration d'un namespace -----
let purgeNs="", purgeRows=[];
const KIND_LBL={auto:"Automatic", manual:"Manual", pre_restore:"Before restore"};
function purgeSync(){ $("#purgeGo").disabled = !document.querySelectorAll(".purgeChk:checked").length; }
async function openPurgeModal(ns){
  purgeNs=ns; purgeRows=[];
  $("#mPurgeTitle").innerHTML=esc("Saved versions")+'<span class="sep">›</span>'+esc(ns);
  $("#purgeMsg").innerHTML=""; $("#purgeList").innerHTML='<div class="hint"><span class="spin"></span></div>';
  openModal("mPurge");
  const r=await get("/api/backups?ns="+encodeURIComponent(ns));
  purgeRows=r.backups||[];
  if(!purgeRows.length){ $("#purgeList").innerHTML='<div class="hint">No saved version.</div>'; purgeSync(); return; }
  $("#purgeList").innerHTML=`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule)"><table class="ht"><thead><tr><th class="cb"></th><th>Date</th><th>Type</th><th class="ctr">Volumes</th></tr></thead><tbody>`+
    purgeRows.map((b,i)=>{ const ix=b.index||{};
      return `<tr><td class="cb"><input type="checkbox" class="purgeChk" data-i="${i}"></td><td>${esc(ix.created ? new Date(ix.created).toLocaleString(): b.timestamp)}${i===0?' <span class="hint">(most recent)</span>':''}</td>
        <td>${esc(KIND_LBL[ix.kind]||"—")}${ix.partial?' <span class="hint">partial</span>':''}</td><td class="ctr">${(ix.volumes||[]).length}</td></tr>`; }).join("")+`</tbody></table></div>`;
  document.querySelectorAll(".purgeChk").forEach(c=>c.onchange=purgeSync);
  purgeSync();
}
$("#purgeOld").onclick=()=>{ document.querySelectorAll(".purgeChk").forEach(c=>c.checked = +c.dataset.i>0); purgeSync(); };
$("#purgeGo").onclick=async()=>{
  const sel=[...document.querySelectorAll(".purgeChk:checked")].map(c=>purgeRows[+c.dataset.i]);
  if(!sel.length) return;
  const all = sel.length===purgeRows.length;
  if(!(await confirmDanger({title:"Delete versions", lines:[
     "<b>"+sel.length+"</b> configuration version(s) of <b>"+esc(purgeNs)+"</b> will be permanently deleted.",
     all ? "<b>All</b> versions are selected: this application can no longer be restored from the tool.": "The volume data (HYCU) is not touched."]}))) return;
  const b=$("#purgeGo"); b.disabled=true;
  const r=await post("/api/backups/delete",{ns:purgeNs, paths:sel.map(x=>x.path)});
  $("#purgeMsg").innerHTML = r.ok ? `<div class="note" style="margin-top:8px">${esc(r.removed+" version(s) deleted.")}</div>`: errBox(r.error);
  await openPurgeModal(purgeNs);
  if(r.removed) loadApps(true);
};
$("#actPurge").onclick=async()=>{ const a=selAppObjs()[0]; await ensureCluster(a); openPurgeModal(appNs(a)); };
$("#actVerify").onclick=async()=>{ const a=selAppObjs()[0]; await ensureCluster(a); gotoVerify(appNs(a), false); };

// ============================ Modale Sauvegarde ============================
// Actions principales dans le pied de modale (comme HYCU): on y DÉPLACE les boutons
// existants — leurs gestionnaires d'événements suivent l'élément.
$("#mBackupFoot").append($("#bkRunAll"), $("#bkRun"));
let bkSel=[], bkObjs=[];
function openBackupModal(list, objs){
  bkSel=(list||[]).filter(Boolean);
  bkObjs=(objs && objs.length===bkSel.length) ? objs: bkSel.map(n=>({name:n, cluster_id:ACTIVE_CID}));
  const multi=bkSel.length>1, multiCl=new Set(bkObjs.map(o=>o.cluster_id)).size>1;
  $("#bkOut").innerHTML="";
  $("#bkNsRow").style.display = multi ? "none": "";
  $("#bkSelInfo").style.display = multi ? "": "none";
  $("#bkRun").style.display = multi ? "none": "";
  $("#bkRunAll").style.display = multi ? "none": "";
  $("#bkRunSel").style.display = multi ? "": "none";
  if(multi){ $("#bkSelList").textContent=bkObjs.map(o=>multiCl ? o.name+" ("+(o.cluster||o.cluster_id)+")": o.name).join(", ");
             $("#bkRunSel").textContent="Back up the selection ("+bkSel.length+")"; }
  else if(bkSel[0]){ state.ns=bkSel[0]; applyGlobalNs(); }
  openModal("mBackup");
}
$("#bkRunSel").onclick=async()=>{
  const b=$("#bkRunSel"), dest=$("#bkDest").value.trim(); b.disabled=true;
  const multiCl=new Set(bkObjs.map(o=>o.cluster_id)).size>1;
  let lines="", ok=0;
  for(const o of bkObjs){
    const lbl=multiCl ? o.name+" ("+(o.cluster||o.cluster_id)+")": o.name;
    $("#bkOut").innerHTML=`<div class="hint"><span class="spin"></span>${esc(lbl)}…</div><ul class="dlist">${lines}</ul>`;
    const r=await post("/api/backup",{ns:o.name, dest}, o.cluster_id);
    if(r.ok) ok++;
    lines+=`<li><span class="k" style="display:flex;gap:10px;align-items:center">${stIc(r.ok?"ok":"ko")}${esc(lbl)}</span>`+
           `<span class="v" style="font-weight:400">${r.ok ? r.count+" volume(s)": esc(r.error||"")}</span></li>`;
  }
  $("#bkOut").innerHTML=`<div class="note">${ok}/${bkObjs.length} namespace(s) backed up.</div><ul class="dlist" style="margin-top:8px">${lines}</ul>`;
  b.disabled=false;
};

// ============================ Modale Set Policy ============================
// ----- Politique de sauvegarde de la CONFIGURATION du/des namespace(s) de la fenêtre -----
let cfgPolNs=[], cfgPolAll=[];
async function loadCfgPolicy(nsList){
  cfgPolNs=nsList.filter(Boolean);
  const sel=$("#bkCfgPol"); $("#bkCfgPolMsg").textContent="";
  sel.innerHTML='<option value="">…</option>'; sel.disabled=true;
  const [ab, mem]=await Promise.all([get("/api/auto_backup"), get("/api/policy_members")]);
  cfgPolAll=(ab&&ab.policies)||[];
  const members=(mem&&mem.ok)?(mem.members||{}):{};
  const cur=new Set(cfgPolNs.map(ns=>{ for(const k in members){ if((members[k]||[]).includes(ns)) return k; } return ""; }));
  const curOne = cur.size===1 ? [...cur][0]: null;
  const defLbl = "Default"+(ab && ab.enabled ? " · "+Math.round(ab.interval_hours||24)+" h": " (disabled)");
  sel.innerHTML=(curOne===null?'<option value="__mixed">(different policies)</option>':"")+
    `<option value="">${esc(defLbl)}</option>`+
    cfgPolAll.map(p=>`<option value="${esc(p.name)}">${esc(p.name+" · "+(+p.interval_hours)+" h · "+p.keep+" versions")}</option>`).join("");
  sel.value = curOne===null ? "__mixed": curOne;
  sel.disabled=false;
}
$("#bkCfgPolSave").onclick=async()=>{
  const choice=$("#bkCfgPol").value;
  if(choice==="__mixed" || !cfgPolNs.length) return;
  const list=cfgPolAll.map(p=>{
    const nss=(p.namespaces||[]).filter(n=>!cfgPolNs.includes(n));
    if(p.name===choice) cfgPolNs.forEach(n=>{ if(!nss.includes(n)) nss.push(n); });
    return {name:p.name, namespaces:nss, label_selector:p.label_selector||"", interval_hours:+p.interval_hours,
            keep:+p.keep, enabled:p.enabled!==false, hycu_policy:p.hycu_policy||"", hycu_policy_name:p.hycu_policy_name||""};
  }).filter(p=>p.namespaces.length || p.label_selector);
  const dropped=cfgPolAll.filter(p=>!list.some(x=>x.name===p.name)).map(p=>p.name);
  if(dropped.length && !(await confirmDanger({title:"Policy without namespace", lines:[
      "Policy <b>"+esc(dropped.join(", "))+"</b> would no longer have any namespace or selector: it will be deleted."]}))) return;
  const b=$("#bkCfgPolSave"); b.disabled=true;
  const r=await post("/api/config",{config:{backup_policies:list}});
  b.disabled=false;
  if(!r.ok){ $("#bkCfgPolMsg").innerHTML=errBox(r.error); return; }
  await loadCfgPolicy(cfgPolNs);
  const now=$("#bkCfgPol").value;
  $("#bkCfgPolMsg").textContent = (now===choice) ? "Saved."
   : "Saved — but “"+(now||"Default")+"” still applies through its label selector.";
};
function openPolicyModal(ns){
  // ns: un namespace (chaîne) ou une liste de namespaces (plusieurs applications en une fois).
  bkNsList = Array.isArray(ns) ? ns.slice(): [];
  loadCfgPolicy(bkNsList.length ? bkNsList: [ns || $("#bkNs").value]);
  if(bkNsList.length){
    clearBkProtect();
    $("#mPolicyTitle").innerHTML=esc("Set Policy")+'<span class="sep">›</span>'+esc(bkNsList.length+" applications")
      +' <span class="hint" style="font-weight:400">'+esc(bkNsList.join(", "))+'</span>';
    openModal("mPolicy");
    if(conn.hycu && conn.hycu.connected) setTimeout(()=>$("#bkMatch").click(), 30);
    return;
  }
  if(ns){ state.ns=ns; applyGlobalNs(); $("#bkNs").value=ns;
    if($("#bkNs").value!==ns){                 // namespace disparu / kubectl en panne
      clearBkProtect(); openModal("mPolicy");
      $("#bkMatchOut").innerHTML=errBox("Namespace “"+ns+"” not found in the list — refresh Applications (kubectl unavailable?).");
      return;
    } }
  clearBkProtect();
  $("#mPolicyTitle").innerHTML=esc("Set Policy")+(ns ? '<span class="sep">›</span>'+esc(ns): "");
  openModal("mPolicy");
  if(conn.hycu && conn.hycu.connected) setTimeout(()=>$("#bkMatch").click(), 30);   // analyse: lecture seule
}

// ============================ Bulk restore (same cluster) ============================
// Plan (lecture seule) -> Simuler (journal, arrière-plan) -> Lancer (réel: simulation
// du même plan exigée par le serveur, confirmation du contexte); suivi par polling,
// arrêt propre et reprise (les namespaces déjà recréés ne sont jamais refaits).
let bulkPlan=null, bulkStatus=null, bulkTimer=null, bulkWasRunning=false, bulkPollErrors=0;
function bulkNowLocal(){ const d=new Date(); const p=n=>String(n).padStart(2,"0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; }
function bulkExclude(){ return ($("#bulkExclude").value||"").split(",").map(s=>s.trim()).filter(Boolean); }
function openBulkModal(){
  bulkPlan=null; $("#bulkAsOf").value=bulkNowLocal(); $("#bulkPlanOut").innerHTML=""; $("#bulkRunOut").innerHTML="";
  $("#bulkCluster").textContent=ctxInfo.context||"—";
  openModal("mBulk"); bulkSyncBtns(); bulkPoll();
}
$("#actBulk").onclick=openBulkModal;
function bulkSamePlan(j){
  return !!(j && bulkPlan && j.as_of===bulkPlan.as_of_iso && j.items.length===bulkPlan.items.length
            && j.items.every((it,i)=>it.ns===bulkPlan.items[i].ns));
}
function bulkSyncBtns(){
  const running=!!(bulkStatus&&bulkStatus.running), j=bulkStatus&&bulkStatus.journal, c=bulkStatus&&bulkStatus.counts;
  const n=!!(bulkPlan&&bulkPlan.items.length);
  const simOk=!!(j && j.dry && j.done && !j.stopped && c && c.failed===0 && bulkSamePlan(j));
  $("#bulkSim").disabled = !n || running;
  $("#bulkReal").disabled = !n || running || !simOk || dry();
  $("#bulkReal").title = dry() ? "Turn off the Simulation banner to start the real run.": (!simOk ? "Simulate this plan first (without failure).": "");
  $("#bulkStop").style.display = running ? "": "none";
  $("#bulkResume").style.display = (j && !running && !j.done && j.items.some(it=>it.status!=="done")) ? "": "none";
}
async function bulkMakePlan(){
  const b=$("#bulkPlanBtn"); b.disabled=true;
  $("#bulkPlanOut").innerHTML='<div class="hint"><span class="spin"></span>Analysing backups and cluster…</div>';
  const r=await post("/api/bulk/plan",{as_of:$("#bulkAsOf").value, exclude:bulkExclude()});
  b.disabled=false;
  if(!r.ok){ bulkPlan=null; $("#bulkPlanOut").innerHTML=errBox(r.error); bulkSyncBtns(); return; }
  bulkPlan=r; $("#bulkPlanOut").innerHTML=bulkRenderPlan(r); bulkSyncBtns();
}
$("#bulkPlanBtn").onclick=bulkMakePlan;
function bulkRenderPlan(r){
  const rows=r.items.map(it=>`<tr><td style="color:var(--strong);font-weight:500">${esc(it.ns)}</td><td>${esc((it.created||it.timestamp||"").replace("T"," ").slice(0,16))}</td>
     <td>${it.stateless?'<span class="badge b-pending">Stateless</span>':(it.volumes.length+" volume(s)")}${it.partial?' <span class="badge b-lost">partial</span>':''}</td>
     <td>${(it.warnings||[]).length?'<span class="ko">⚠ '+esc(it.warnings.join(" · "))+'</span>':'<span class="ok">✓</span>'}</td></tr>`).join("");
  const sk=(r.skipped||[]).map(s=>`<li><b>${esc(s.ns)}</b> — ${esc(s.reason)}</li>`).join("");
  const warnN=r.items.filter(it=>(it.warnings||[]).length).length;
  return `<div class="note"><b>${r.items.length}</b> namespace(s) to recreate on <b>${esc(r.context||r.cluster||"?")}</b> · reference time ${esc((r.as_of_iso||"").replace("T"," "))}${warnN?` · <span class="ko">${warnN} with a warning</span>`:""}${r.vault_unlocked?"":' · <span class="ko">vault locked</span>'}${r.hycu?"":' · <span class="hint">HYCU not connected: vanished Volume Groups will not be restored</span>'}</div>
    ${r.items.length?`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule);max-height:300px;overflow:auto"><table class="ht" id="bulkPlanTable"><thead><tr><th>Namespace</th><th>Backup</th><th>Content</th><th>Warnings</th></tr></thead><tbody>${rows}</tbody></table></div>`:'<div class="hint">No deleted namespace with a backup prior to the reference time.</div>'}
    ${sk?`<details style="margin-top:8px"><summary class="hint">${(r.skipped||[]).length} namespace(s) skipped</summary><ul class="dlist" style="margin-top:6px">${sk}</ul></details>`:""}`;
}
async function bulkStart(dryRun){
  let confirmedCtx="";
  if(!dryRun){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res=await confirmDanger({title:"Confirm the bulk restore", requireText:needCtx, lines:[
      "<b>"+bulkPlan.items.length+"</b> namespace(s) will be RECREATED on <b>"+esc(ctxInfo.context||"?")+"</b> from their backups.",
      "Sequential, journaled execution; vanished Volume Groups will be restored by HYCU (real operations).",
      "Present namespaces are left untouched."]});
    if(!res) return; if(typeof res==="string") confirmedCtx=res;
  }
  const body={as_of:$("#bulkAsOf").value, exclude:bulkExclude(), dry:dryRun};
  if(!dryRun && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const r=await post("/api/bulk/run", body);
  if(!r.ok){ $("#bulkRunOut").innerHTML=errBox(r.error); return; }
  bulkPoll();
}
$("#bulkSim").onclick=()=>bulkStart(true);
$("#bulkReal").onclick=()=>bulkStart(false);
$("#dry").addEventListener("change",()=>{ if($("#mBulk").style.display!=="none") bulkSyncBtns(); });   // bandeau Simulation
$("#bulkStop").onclick=async()=>{ const r=await post("/api/bulk/stop",{}); if(!r.ok) $("#bulkRunOut").insertAdjacentHTML("afterbegin", errBox(r.error)); };
$("#bulkResume").onclick=async()=>{
  const j=bulkStatus&&bulkStatus.journal; if(!j) return;
  let confirmedCtx="";
  if(!j.dry){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res=await confirmDanger({title:"Resume the bulk restore", requireText:needCtx, lines:[
      "The remaining namespaces (pending, stopped or failed) will be recreated; those already recreated are not redone."]});
    if(!res) return; if(typeof res==="string") confirmedCtx=res;
  }
  const body={resume:true, dry:j.dry}; if(!j.dry && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const r=await post("/api/bulk/run", body);
  if(!r.ok){ $("#bulkRunOut").innerHTML=errBox(r.error); return; }
  bulkPoll();
};
async function bulkPoll(){
  clearTimeout(bulkTimer);
  if($("#mBulk").style.display==="none") return;
  const st=await get("/api/bulk/status");
  if(!st.ok){                                   // coupure passagère: on réessaie (borné), sans figer les boutons
    if(++bulkPollErrors<=30){ bulkTimer=setTimeout(bulkPoll, 3000); }
    else { $("#bulkRunOut").insertAdjacentHTML("beforeend", '<div class="hint">Tracking stopped (server unreachable) — reopen the window to resume tracking.</div>'); }
    return;
  }
  bulkPollErrors=0;
  bulkStatus=st; bulkRenderStatus(st); bulkSyncBtns();
  if(st.running){ bulkWasRunning=true; bulkTimer=setTimeout(bulkPoll, 2000); }
  else if(bulkWasRunning){ bulkWasRunning=false; loadApps(true); }   // namespaces recréés: inventaire à jour
}
function bulkRenderStatus(st){
  const j=st.journal; if(!j){ $("#bulkRunOut").innerHTML=""; return; }
  const c=st.counts, pct=c.total?Math.round(100*(c.done+c.failed)/c.total):0;
  const IC={done:"ok",failed:"ko",running:"run",pending:"na",stopped:"wn"};
  const head = st.running ? '<span class="spin"></span> Running': j.stopped ? "Stopped": j.done ? (c.failed ? "Finished with failures": "Finished"): "Interrupted";
  $("#bulkRunOut").innerHTML=`<div class="${j.dry?'warnbox':'note'}" id="bulkHead"><b>${j.dry?"Simulation":"Live"}</b> · ${head} · ${c.done+c.failed} / ${c.total} (${c.failed} failure(s)) · reference time ${esc((j.as_of||"").replace("T"," "))}${j.started?" · started "+esc(j.started.replace("T"," ")):""}</div>
    <div style="height:6px;background:var(--rule);border-radius:3px;margin:6px 0 10px"><div style="height:6px;width:${pct}%;background:#41327C;border-radius:3px"></div></div>
    <div class="tcard" style="box-shadow:none;border:1px solid var(--rule);max-height:320px;overflow:auto"><table class="ht" id="bulkStatusTable"><thead><tr><th>Namespace</th><th>State</th><th>Detail</th></tr></thead><tbody>${
      j.items.map(it=>`<tr><td style="color:var(--strong);font-weight:500">${esc(it.ns)}</td><td>${stIc(IC[it.status]||"na", it.status)} ${esc(it.status)}</td>
        <td>${it.error?'<span class="ko">'+esc(it.error)+'</span>':''}${(it.run_warnings||[]).length?'<div class="hint">⚠ '+esc(it.run_warnings.join(" · "))+'</div>':''}${(it.log||[]).length?`<details><summary class="hint">${it.log.length} step(s)</summary>${renderLog(it.log)}</details>`:''}</td></tr>`).join("")}</tbody></table></div>`;
}

// ============================ Modale Sources (engrenage) ============================
const SRC=[{key:"hycu", name:"HYCU", type:"Backup & restore (REST API)"},
           {key:"nutanix", name:"Prism Element", type:"Nutanix — Volume Groups (v2 API)"},
           {key:"prismcentral", name:"Prism Central", type:"Nutanix — multi-cluster (v3/v4 API)"},
           {key:"s3", name:"S3 object storage", type:"Backup export (optional)"},
           {key:"vault", name:"Credentials vault", type:"Encrypted storage (optional)"}];
let srcSel="hycu";
const CHK_SVG='<svg width="14" height="14" viewBox="0 0 18 18" aria-hidden="true"><path d="M4.5 9.4l3 3 6-6.4" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
function clById(id){ return CLUSTERS.find(c=>c.id===id); }
function clType(c){
  if(c.local) return "Kubernetes — local configuration";
  if(c.source==="nkp") return "Kubernetes — NKP"+(c.workspace?" (workspace "+c.workspace+")":"");
  return "Kubernetes — imported kubeconfig";
}
function clStatusIc(c){
  const h=c.health;
  if(h && !h.ok) return stIc("ko","Cluster unreachable (checked "+fmtAgo(h.at)+"): "+(h.error||""));
  if(c.local) return c.configured ? stIc("ok","Context: "+(c.context||"")): stIc("na","Not configured");
  const a=c.auth||{}, w=(a.warnings||[]).concat(c.warning?[c.warning]:[]).join(" ");
  if(a.level==="error") return stIc("ko", w);
  if(a.level==="warn" || c.warning) return stIc("wn", w);
  if(h && h.ok) return stIc("ok","Reachable ("+fmtAgo(h.at)+") · authentication: "+(a.type||"?"));
  return stIc("ok","Authentication: "+(a.type||"?"));
}
function renderSourcesTable(){
  const body=$("#srcBody"); if(!body) return;
  const row=(key, name, type, url, st)=>`<tr class="clk${key===srcSel?' sel':''}" data-key="${esc(key)}"><td>${name}</td><td>${esc(type)}</td>`+
           `<td><code>${esc(url||"—")}</code></td><td class="ctr">${st}</td></tr>`;
  let h=`<tr class="srcsec"><td colspan="4">HYCU &amp; Nutanix</td></tr>`;
  h+=SRC.map(s=>{
    let url="—", st;
    if(s.key==="vault"){
      st = (conn.vault && conn.vault.present) ? stIc("ok","Vault present"): stIc("na","No vault");
    } else {
      const x=conn[s.key]||{}; url=x.url||"—";
      if(s.key==="s3" && x.url) url=x.url+"/"+(x.bucket||"");
      st = x.connected ? stIc("ok","Connected"): (x.configured ? stIc("wn","Configured, not connected"): stIc("na","Not configured"));
      if(s.key==="s3" && x.connected && !x.auto_upload) st=stIc("wn","Connected — automatic export disabled");
    }
    return row(s.key, esc(s.name), s.type, url, st);
  }).join("");
  h+=`<tr class="srcsec"><td colspan="4">Kubernetes clusters</td></tr>`;
  h+=CLUSTERS.map(c=>row("cluster:"+c.id, esc(c.name)+(c.id===ACTIVE_CID?'<span class="tag">ACTIVE</span>':''),
        clType(c), c.local ? (c.kubeconfig_path||"default kubeconfig"): c.server, clStatusIc(c))).join("");
  body.innerHTML=h;
  body.querySelectorAll("tr.clk").forEach(tr=>tr.onclick=()=>{ srcSel=tr.dataset.key; showSourceCard(); renderSourcesTable(); });
}
function showSourceCard(){
  const card = srcSel.indexOf("cluster:")===0 ? "cluster": srcSel;
  document.querySelectorAll("#tab-connect > .card").forEach(c=>c.style.display = c.dataset.card===card ? "": "none");
  if(card==="cluster") renderClusterCard(srcSel.slice(8));
  if(card==="nkp") $("#nkpMgmt").textContent = ctxInfo.context || "—";
}
function openSources(i){
  if(typeof i==="number") srcSel=SRC[i].key;
  else if(typeof i==="string") srcSel=i;
  renderSourcesTable(); showSourceCard(); openModal("mSources");
}
$("#clAddBtn").onclick=()=>openSources("cluster-add");
$("#nkpBtn").onclick=()=>openSources("nkp");

// ----- Clusters Kubernetes: liste, sélecteur de la barre du haut, cluster actif -----
async function loadClusters(){
  const r=await get("/api/clusters","local");
  if(r && r.ok) CLUSTERS=r.clusters||CLUSTERS;
  if(!clById(ACTIVE_CID)) ACTIVE_CID="local";      // cluster retiré / session verrouillée
  renderClMenu(); renderSourcesTable(); updateScopeSeg();
  return CLUSTERS;
}
function renderCtx(){
  $("#ctx").textContent = ctxInfo.context || "unavailable";
  $("#ctxWarn").innerHTML = (ctxInfo.context && ctxInfo.allowed && ctxInfo.allowed.length && !ctxInfo.context_ok)
    ? ' <span class="bad">⚠ not in allowed list</span>'
   : ((ctxInfo.auth && ctxInfo.auth.level==="error") ? ' <span class="bad">⚠ token expired</span>': '');
  $("#ctxLink").title = "Active Kubernetes cluster"+(ctxInfo.workspace?(" — workspace "+ctxInfo.workspace):"")+" — click to choose another one";
}
function renderClMenu(){
  const m=$("#clMenu");
  m.innerHTML=CLUSTERS.map(c=>`<div class="cli${c.id===ACTIVE_CID?' on':''}" data-cid="${esc(c.id)}" role="menuitem">`+
      `<span class="chk">${c.id===ACTIVE_CID?CHK_SVG:''}</span><span>${esc(c.name)}</span>`+
      `<span class="ws">${esc(c.local ? "local configuration": (c.workspace || "imported kubeconfig"))}</span></div>`).join("")+
    `<div class="msep"></div><div class="cli act" data-act="add" role="menuitem"><span class="chk"></span>Add a Kubernetes cluster…</div>`+
    `<div class="cli act" data-act="manage" role="menuitem"><span class="chk"></span>Manage clusters…</div>`;
  m.querySelectorAll(".cli").forEach(el=>el.onclick=async e=>{
    e.stopPropagation(); m.style.display="none";
    if(el.dataset.act==="add") return openSources("cluster-add");
    if(el.dataset.act==="manage") return openSources("cluster:"+ACTIVE_CID);
    if(el.dataset.cid!==ACTIVE_CID) await setActiveCluster(el.dataset.cid);
  });
}
function toggleClMenu(){
  const m=$("#clMenu");
  if(m.style.display==="block"){ m.style.display="none"; return; }
  $("#gearMenu").style.display="none"; $("#helpMenu").style.display="none";
  renderClMenu();
  const r=$("#ctxLink").getBoundingClientRect();
  m.style.right=Math.max(8, window.innerWidth-r.right-10)+"px";
  m.style.display="block";
}
document.addEventListener("click",()=>{ ["clMenu","gearMenu","helpMenu"].forEach(i=>$("#"+i).style.display="none"); });
async function setActiveCluster(cid){
  if(!clById(cid)) return;
  ACTIVE_CID=cid; savePref("cluster", cid);
  if(vfTrack) vfStop();                             // ni à un changement de cluster
  ["mBackup","mPolicy","mRestore"].forEach(closeModal);
  if(appsScope!=="all") appsSel.clear();
  state.ns=null;
  ctxInfo=await get("/api/context");
  renderCtx(); renderKubeBanner(); renderClMenu(); renderSourcesTable();
  if($("#mSources").style.display!=="none") showSourceCard();
  await refreshNamespaces();
  onPageShown(curPage);
}
// Coffre déverrouillé: les clusters mémorisés reviennent -> reprendre le cluster préféré.
async function afterVaultLoad(){
  await loadClusters();
  const p=prefs().cluster;
  if(p && p!==ACTIVE_CID && clById(p)) await setActiveCluster(p);
}
function renderClusterCard(cid){
  const c=clById(cid); $("#clDErr").innerHTML="";
  if(!c){ $("#clDTitle").textContent="Cluster"; $("#clDBody").innerHTML='<div class="hint">Cluster not found.</div>'; return; }
  $("#clDTitle").textContent=c.name;
  const li=(k,v)=>`<li><span class="k">${k}</span><span class="v">${v}</span></li>`;
  let h='<ul class="dlist">';
  h+=li("Type", esc(clType(c)));
  if(c.local){
    h+=li("kubectl context", c.context?`<code>${esc(c.context)}</code>`:"—");
    h+=li("Kubeconfig", `<code>${esc(c.kubeconfig_path||"default kubeconfig")}</code>`);
  } else {
    h+=li("kubectl context", `<code>${esc(c.context)}</code>`);
    h+=li("API server", `<code>${esc(c.server||"—")}</code>`);
    if(c.workspace) h+=li("NKP workspace", esc(c.workspace));
    if(c.management) h+=li("Management cluster", esc(c.management));
    h+=li("Authentication", esc((c.auth||{}).type||"?")+" "+clStatusIc(c));
  }
  h+=li("Backups", c.local ? `<code>hycu-backups/_contexts/${esc(c.context||"…")}/&lt;namespace&gt;/</code>`: `<code>hycu-backups/_clusters/${esc(c.id)}/&lt;namespace&gt;/</code>`);
  if(c.health) h+=li("Last health check", (c.health.ok?stIc("ok","Reachable"):stIc("ko",esc(c.health.error||"")))+" "+esc(fmtAgo(c.health.at)));
  h+='</ul>';
  if(c.health && !c.health.ok) h+=`<div class="err" style="margin-top:10px">Cluster unreachable at last check: ${esc(c.health.error||"")}</div>`;
  const w=((c.auth||{}).warnings||[]).concat(c.warning?[c.warning]:[]);
  if(w.length) h+=`<div class="warnbox" style="margin-top:10px">⚠ ${w.map(esc).join("<br>")}</div>`;
  if(c.local && !c.configured) h+=`<div class="warnbox" style="margin-top:10px">No local kubectl context: add a cluster with its kubeconfig, or configure kubectl (Settings).</div>`;
  $("#clDBody").innerHTML=h;
  $("#clUse").disabled = c.id===ACTIVE_CID;
  $("#clUse").textContent = c.id===ACTIVE_CID ? "Active cluster": "Set as active cluster";
  $("#clRemove").style.display = c.local ? "none": "";
  $("#clLocalCfg").style.display = c.local ? "": "none";
  $("#clUse").onclick=()=>setActiveCluster(c.id);
  $("#clLocalCfg").onclick=()=>{ closeModal("mSources"); switchTab("settings"); };
  $("#clRemove").onclick=async()=>{
    if(!confirm("Remove cluster “"+c.name+"”? Its kubeconfig is forgotten; its backups stay on disk.")) return;
    const r=await post("/api/clusters/remove",{id:c.id},"local");
    if(!r.ok){ $("#clDErr").innerHTML=errBox(r.error); return; }
    const wasActive = c.id===ACTIVE_CID;
    await loadClusters();
    srcSel="cluster:"+(wasActive?"local":ACTIVE_CID);
    if(wasActive) await setActiveCluster("local");
    showSourceCard(); renderSourcesTable();
  };
}

// ----- Ajout d'un cluster (kubeconfig fichier / collé) -----
let clInspectT=null, clCtxs=[];
function clCtxInfo(){
  const c=clCtxs.find(x=>x.name===$("#clCtx").value); if(!c){ $("#clCtxInfo").innerHTML=""; return; }
  const a=c.auth||{};
  $("#clCtxInfo").innerHTML=`<ul class="dlist" style="margin-top:8px"><li><span class="k">API server</span><span class="v"><code>${esc(c.server||"—")}</code></span></li>`+
    `<li><span class="k">Authentication</span><span class="v">${esc(a.type||"?")} ${a.level==="error"?stIc("ko"):a.level==="warn"?stIc("wn"):stIc("ok")}</span></li></ul>`+
    ((a.warnings||[]).length?`<div class="warnbox" style="margin-top:8px">⚠ ${a.warnings.map(esc).join("<br>")}</div>`:"");
  if(!$("#clName").value.trim() || $("#clName").dataset.auto==="1"){
    $("#clName").value=(c.cluster||c.name||"").replace(/[^A-Za-z0-9._-]+/g,"-").slice(0,63); $("#clName").dataset.auto="1"; }
}
async function clInspect(){
  const kc=$("#clKc").value; $("#clErr").innerHTML="";
  if(!kc.trim()){ $("#clCtxWrap").style.display="none"; clCtxs=[]; return; }
  const r=await post("/api/clusters/inspect",{kubeconfig:kc},"local");
  if(!r.ok){ $("#clCtxWrap").style.display="none"; clCtxs=[]; $("#clErr").innerHTML=errBox(r.error); return; }
  clCtxs=r.contexts||[];
  $("#clCtx").innerHTML=clCtxs.map(c=>`<option value="${esc(c.name)}">${esc(c.name)}</option>`).join("");
  $("#clCtx").value=r.current||(clCtxs[0]||{}).name||"";
  $("#clCtxWrap").style.display="block"; clCtxInfo();
}
$("#clKc").oninput=()=>{ clearTimeout(clInspectT); clInspectT=setTimeout(clInspect, 500); };
$("#clCtx").onchange=clCtxInfo;
$("#clName").oninput=()=>{ $("#clName").dataset.auto=""; };
$("#clFile").onchange=()=>{
  const f=$("#clFile").files[0]; if(!f) return;
  if(f.size>1024*1024){ $("#clErr").innerHTML=errBox("Kubeconfig too large (1 MB max)."); return; }
  const rd=new FileReader(); rd.onload=()=>{ $("#clKc").value=rd.result; $("#clFile").value=""; clInspect(); }; rd.readAsText(f);
};
$("#clAdd").onclick=async()=>{
  const b=$("#clAdd"); $("#clErr").innerHTML="";
  if(!$("#clKc").value.trim()){ $("#clErr").innerHTML=errBox("Load or paste a kubeconfig first."); return; }
  b.disabled=true; b.innerHTML='<span class="spin"></span>Testing connection…';
  const r=await post("/api/clusters/add",{name:$("#clName").value.trim(), kubeconfig:$("#clKc").value,
                                          context:$("#clCtx").value||""},"local");
  b.disabled=false; b.textContent="Test & add";
  if(!r.ok){ $("#clErr").innerHTML=errBox(r.error); if(r.need_context) clInspect(); return; }
  $("#clKc").value=""; $("#clName").value=""; $("#clName").dataset.auto=""; $("#clCtxWrap").style.display="none"; clCtxs=[];
  await loadClusters();
  srcSel="cluster:"+r.cluster.id; renderSourcesTable(); showSourceCard();
  $("#clDErr").innerHTML=`<div class="note">Cluster added. Choose “Set as active cluster” to use it, or select it in the top bar.</div>`;
};

// ----- Découverte NKP (workspaces -> clusters) depuis le cluster de management actif -----
let nkpData=null;
function nkpSync(){
  const n=document.querySelectorAll(".nkpChk:checked").length;
  $("#nkpImport").disabled = !(n && $("#nkpAck").checked);
  $("#nkpImport").textContent = n ? "Import selection ("+n+")": "Import selection";
}
$("#nkpAck").onchange=nkpSync;
$("#nkpDiscover").onclick=()=>nkpLoad(false);
async function nkpLoad(keepRes){
  const b=$("#nkpDiscover"); if(!keepRes) $("#nkpRes").innerHTML=""; $("#nkpImportWrap").style.display="none";
  b.disabled=true; $("#nkpOut").innerHTML='<div class="hint"><span class="spin"></span>Reading workspaces…</div>';
  const r=await get("/api/nkp/discover"); b.disabled=false; nkpData=r;
  if(!r.ok){ $("#nkpOut").innerHTML=errBox(r.error); return; }
  const cl=r.clusters||[];
  if(!cl.length){ $("#nkpOut").innerHTML='<div class="hint">No cluster found in the workspaces.</div>'; return; }
  let h=`<div class="tcard" style="box-shadow:none;border:1px solid var(--rule);margin-top:12px"><table class="ht"><thead><tr><th class="cb"></th><th>Cluster</th><th>Phase</th><th>Status</th></tr></thead><tbody>`, ws=null;
  cl.forEach((c,i)=>{
    if(c.workspace!==ws){ ws=c.workspace; h+=`<tr class="grp"><td colspan="4">Workspace <span class="gs">›</span>${esc(ws)}</td></tr>`; }
    const dis=c.host||!!c.registered;
    const st=c.host ? "Management cluster (active)": (c.registered ? "Already imported ("+c.registered+")": "—");
    h+=`<tr><td class="cb"><input type="checkbox" class="nkpChk" data-i="${i}" ${dis?"disabled":""}></td>`+
       `<td style="color:var(--strong)">${esc(c.name)}</td><td>${esc(c.phase||"—")}</td><td>${esc(st)}</td></tr>`;
  });
  $("#nkpOut").innerHTML=h+"</tbody></table></div>";
  document.querySelectorAll(".nkpChk").forEach(x=>x.onchange=nkpSync);
  $("#nkpImportWrap").style.display="block"; $("#nkpAck").checked=false; nkpSync();
}
$("#nkpImport").onclick=async()=>{
  const items=[...document.querySelectorAll(".nkpChk:checked")].map(x=>nkpData.clusters[+x.dataset.i])
    .map(c=>({namespace:c.namespace, name:c.name, secret:c.secret, workspace:c.workspace}));
  if(!items.length) return;
  const b=$("#nkpImport"); b.disabled=true; b.innerHTML='<span class="spin"></span>Import…';
  const r=await post("/api/nkp/import",{ack:$("#nkpAck").checked, items});
  nkpSync();
  const res=r.results||[];
  $("#nkpRes").innerHTML=(r.error&&!res.length?errBox(r.error):"")+(res.length?`<ul class="dlist" style="margin-top:10px">`+res.map(x=>
    `<li><span class="k" style="display:flex;gap:10px;align-items:center">${stIc(x.ok?"ok":"ko")}${esc(x.cluster)}</span>`+
    `<span class="v" style="font-weight:400">${x.ok ? "Imported as “"+esc(x.name)+"”"+(x.warning?" — "+esc(x.warning):""): esc(x.error||"")}</span></li>`).join("")+"</ul>":"");
  await loadClusters();
  if(r.imported) await nkpLoad(true);
};

// ============================ Politiques ============================
let polAll=[], polEditIdx=-1, polMembers={};
function polTarget(p){
  const parts=[];
  if((p.namespaces||[]).length) parts.push(p.namespaces.join(", "));
  if(p.label_selector) parts.push("label "+p.label_selector);
  return parts.join(" · ");
}
function polLast(x){ return x.last_run ? esc(fmtAgo(x.last_run))+" "+stIc(x.last_ok?"ok":"ko", x.last_summary||""): "—"; }
function polMemberHint(name){
  const m=polMembers[name];
  return m ? '<div class="hint" style="margin:2px 0 0">'+(m.length ? esc(m.length+" namespace(s): "+m.slice(0,8).join(", ")+(m.length>8?"…":"")): "no namespace currently")+'</div>': "";
}
async function loadPolicies(){
  await loadAutoBackup();
  const s=await get("/api/auto_backup")||{};
  const on=!!s.enabled;
  polAll=s.policies||[];
  const mem=await get("/api/policy_members"); polMembers=(mem&&mem.ok)?(mem.members||{}):{};
  let h=`<tr class="clk" data-i="-1">
    <td style="color:var(--strong);font-weight:500">Default</td>
    <td>Namespaces without another policy${polMemberHint("")}</td>
    <td>${on ? "Every "+Math.round(s.interval_hours||24)+" h": "—"}</td>
    <td>${abRetLabel(s)}</td><td>—</td>
    <td>${s.last_run ? esc(fmtAgo(s.last_run))+" "+stIc(s.last_ok?"ok":"ko", s.last_summary||""): "—"}</td>
    <td class="ctr">${on ? stIc("ok","Enabled"): stIc("na","Disabled")}</td></tr>`;
  h+=polAll.map((p,i)=>`<tr class="clk" data-i="${i}">
    <td style="color:var(--strong);font-weight:500">${esc(p.name)}</td>
    <td>${esc(polTarget(p))}${polMemberHint(p.name)}</td>
    <td>${"Every "+esc(String(+p.interval_hours))+" h"}</td>
    <td>${p.keep===0 ? "unlimited": esc(p.keep+" versions")}</td>
    <td>${esc(p.hycu_policy_name||"—")}</td>
    <td>${polLast(p)}</td>
    <td class="ctr">${p.enabled ? stIc("ok","Enabled"): stIc("na","Paused")}</td></tr>`).join("");
  $("#polBody").innerHTML=h;
  document.querySelectorAll("#polBody tr.clk").forEach(tr=>tr.onclick=()=>{
    const i=+tr.dataset.i;
    if(i<0){ $("#polEdit").style.display="none"; $("#abEnabled").scrollIntoView({behavior:"smooth", block:"center"}); }
    else polOpen(i);
  });
  if(mem && mem.selector_error) $("#polBody").insertAdjacentHTML("beforeend", `<tr><td colspan="7">${errBox(mem.selector_error)}</td></tr>`);
  if(conn.hycu && conn.hycu.connected){
    $("#polHycu").innerHTML='<div class="hint"><span class="spin"></span></div>';
    const p=await get("/api/hycu/policies");
    $("#polHycu").innerHTML = !p.ok ? errBox(p.error): ((p.policies||[]).length
      ? `<div class="tcard" style="box-shadow:none;border:1px solid var(--rule)"><table class="ht"><thead><tr><th>Name</th><th>UUID</th></tr></thead><tbody>`+
        p.policies.map(x=>`<tr><td>${esc(x.name||"—")}</td><td><code>${esc(x.uuid||"")}</code></td></tr>`).join("")+`</tbody></table></div>`
     : '<div class="hint">No HYCU policy.</div>');
  } else {
    $("#polHycu").innerHTML='<div class="hint">Register the HYCU source (⚙ at the top right) to display its policies.</div>';
  }
}
async function polHycuOptions(sel){
  const box=$("#peHycu");
  box.innerHTML='<option value="">(none)</option>';
  if(!(conn.hycu && conn.hycu.connected)){ box.innerHTML='<option value="">(connect HYCU to choose)</option>'; box.disabled=true; return; }
  box.disabled=false;
  const r=await get("/api/hycu/policies");
  (r.ok ? (r.policies||[]): []).forEach(x=>box.insertAdjacentHTML("beforeend", `<option value="${esc(x.uuid)}">${esc(x.name||x.uuid)}</option>`));
  box.value=sel||"";
}
function polOpen(i){
  polEditIdx=i;
  const p = i>=0 ? polAll[i]: {name:"", namespaces:[], label_selector:"", interval_hours:24, keep:15, enabled:true, hycu_policy:""};
  $("#polEditTitle").textContent = i>=0 ? "Policy “"+p.name+"”": "New policy";
  $("#peName").value=p.name; $("#peNs").value=(p.namespaces||[]).join(", "); $("#peSel").value=p.label_selector||"";
  $("#peInterval").value=p.interval_hours; $("#peKeep").value=p.keep; $("#peEnabled").checked=p.enabled!==false;
  $("#peDelete").style.display = i>=0 ? "": "none"; $("#peMsg").innerHTML="";
  $("#polEdit").style.display="block";
  polHycuOptions(p.hycu_policy);
  $("#polEdit").scrollIntoView({behavior:"smooth", block:"start"});
}
function polClean(p){ return {name:p.name, namespaces:p.namespaces||[], label_selector:p.label_selector||"",
  interval_hours:+p.interval_hours, keep:+p.keep, enabled:p.enabled!==false,
  hycu_policy:p.hycu_policy||"", hycu_policy_name:p.hycu_policy_name||""}; }
async function polSaveList(list){
  const r=await post("/api/config",{config:{backup_policies:list.map(polClean)}});
  if(!r.ok){ $("#peMsg").innerHTML=errBox(r.error||"Could not save."); return false; }
  $("#polEdit").style.display="none";
  await loadPolicies();
  return true;
}
$("#polNew").onclick=()=>polOpen(-1);
$("#peCancel").onclick=()=>{ $("#polEdit").style.display="none"; };
$("#peSave").onclick=async()=>{
  const hy=$("#peHycu");
  const p={name:$("#peName").value.trim(), namespaces:csv($("#peNs").value).map(x=>x.toLowerCase()),
    label_selector:$("#peSel").value.trim(),
    interval_hours:Math.max(0.25, parseFloat(String($("#peInterval").value).replace(",","."))||24),
    keep:Math.max(0, parseInt($("#peKeep").value)||0), enabled:$("#peEnabled").checked,
    hycu_policy:hy.value||"", hycu_policy_name:hy.value ? (hy.options[hy.selectedIndex].textContent||""): ""};
  if(!p.name){ $("#peMsg").innerHTML=errBox("Give the policy a name."); return; }
  if(!p.namespaces.length && !p.label_selector){ $("#peMsg").innerHTML=errBox("Enter namespaces or a label selector."); return; }
  const list=polAll.map(polClean);
  if(polEditIdx>=0) list[polEditIdx]=p; else list.push(p);
  await polSaveList(list);
};
$("#peDelete").onclick=async()=>{
  if(polEditIdx<0) return;
  const p=polAll[polEditIdx];
  if(!(await confirmDanger({title:"Delete the policy", lines:["Policy <b>"+esc(p.name)+"</b> will be deleted. Its namespaces will follow the default policy; existing backups are kept."]}))) return;
  await polSaveList(polAll.filter((_,i)=>i!==polEditIdx).map(polClean));
};
$("#abSave").addEventListener("click", ()=>setTimeout(()=>{ if(curPage==="policies") loadPolicies(); }, 900));

// ============================ Tâches ============================
const JOB_LBL={backup:"Configuration backup", backup_all:"Configuration backup (batch)",
  auto_backup:"Automatic backup", restore_end:"Kubernetes restore (PV/PVC)",
  clone_app:"Application clone", orchestrate_inplace:"In-place restore",
  hycu_restore:"HYCU restore (Volume Group)", hycu_protect:"HYCU protection",
  s3_upload:"S3 export (object storage)", s3_import:"S3 import (repatriation)",
  restore_objects:"Configuration objects restore"};
const JOB_ST={success:["ok","Success"], failed:["ko","Failed"], simulation:["sim","Simulation"]};
let jobsData=null;
async function loadJobs(){
  $("#jobsRefresh").classList.add("busy");
  const r=await get("/api/jobs");
  $("#jobsRefresh").classList.remove("busy");
  jobsData=r; renderJobs(); return r;
}
function jobCounts(r){
  const c=(r&&r.counts)||{};
  const cell=(n, ic, l)=>`<div><div class="n">${n}</div>${ic}<div class="l">${l}</div></div>`;
  return cell(c.success||0, stIc("ok"), "Success") + cell(c.failed||0, stIc("ko"), "Failed") +
         cell(c.simulation||0, stIc("sim"), "Simulation") +
         cell((r&&r.running)||0, stIc("run"), "In progress");
}
function jobRowData(j){
  const st=JOB_ST[j.status]||["na", j.status];
  const app = (j.target_namespace && j.target_namespace!==j.namespace)
    ? esc(j.namespace)+" → "+esc(j.target_namespace): esc(j.namespace||"—");
  const det = j.volumes!=null ? j.volumes+" volume(s)": (j.detail||"");
  return {st, app, det, lbl: JOB_LBL[j.event]||j.event};
}
function renderJobs(){
  const r=jobsData||{};
  $("#jobsCounts").innerHTML=jobCounts(r);
  const q=($("#jobsSearch").value||"").trim().toLowerCase();
  const rows=(r.jobs||[]).filter(j=>!q || (JOB_LBL[j.event]||j.event).toLowerCase().includes(q)
                                        || (j.namespace||"").toLowerCase().includes(q)
                                        || (j.cluster||"").toLowerCase().includes(q));
  $("#jobsInfo").textContent=rows.length+" job(s)"
    +((r.total||0)>(r.jobs||[]).length? " · showing the "+(r.jobs||[]).length+" most recent of "+r.total:"")
    +((r.retention_days||0)>0? " · history kept "+r.retention_days+" d (Settings)":"");
  $("#jobsBody").innerHTML = rows.length ? rows.map(j=>{ const d=jobRowData(j);
      return `<tr><td style="color:var(--strong)">${esc(d.lbl)}</td><td>${d.app}</td><td>${esc(j.cluster==="*"?"All":(j.cluster||"—"))}</td><td>${esc(d.det)}</td>`+
             `<td>${esc(fmtTs(j.ts))}</td><td class="ctr">${stIc(d.st[0], d.st[1])}</td></tr>`; }).join("")
   : `<tr><td colspan="6" class="tempty">No job recorded yet.</td></tr>`;
}
$("#jobsSearch").oninput=renderJobs;
$("#jobsRefresh").onclick=()=>loadJobs();

// ============================ Tableau de bord ============================
function jobsChart(days){
  if(!days || !days.length) return "";
  const W=560, H=170, pl=30, pr=26, pt=10, pb=24, n=days.length;
  const mx=Math.max(4, ...days.map(d=>Math.max(d.success, d.failed, d.simulation)));
  const top=Math.ceil(mx/4)*4;
  const X=i=>pl+i*(W-pl-pr)/Math.max(1, n-1), Y=v=>pt+(H-pt-pb)*(1-v/top);
  let g="";
  for(let k=0;k<=4;k++){ const v=top*k/4, y=Y(v).toFixed(1);
    g+=`<line x1="${pl}" y1="${y}" x2="${W-pr}" y2="${y}" stroke="#D5DAE3" stroke-dasharray="4 4"/>`+
       `<text x="${pl-7}" y="${(+y+4).toFixed(1)}" text-anchor="end" font-size="10" fill="#6B7089">${Math.round(v)}</text>`; }
  const serie=(key, col)=>`<polyline points="${days.map((d,i)=>X(i).toFixed(1)+","+Y(d[key]).toFixed(1)).join(" ")}" fill="none" stroke="${col}" stroke-width="1.6"/>`+
    days.map((d,i)=>`<circle cx="${X(i).toFixed(1)}" cy="${Y(d[key]).toFixed(1)}" r="3" fill="${col}"/>`).join("");
  const lbl=days.map((d,i)=>`<text x="${X(i).toFixed(1)}" y="${H-6}" text-anchor="middle" font-size="10" fill="#6B7089">${d.date.slice(8,10)}/${d.date.slice(5,7)}</text>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="display:block;max-height:240px;margin:0 auto" aria-hidden="true">${g}${serie("simulation","#6688FF")}${serie("failed","#E9605A")}${serie("success","#05A274")}${lbl}</svg>`;
}
function fmtBytes(n){
  if(n==null) return "—";
  const u=["o","Ko","Mo","Go","To"]; let i=0;
  while(n>=1024 && i<u.length-1){ n/=1024; i++; }
  return (i? n.toFixed(1): n)+" "+u[i];
}
function storageBar(pct){
  const col = pct>=90? "var(--red)": pct>=80? "var(--orange)": "var(--green)";
  return `<div style="height:8px;border-radius:4px;background:#EEF0F5;overflow:hidden;margin:4px 0 2px">
    <div style="width:${Math.min(100,pct)}%;height:100%;background:${col}"></div></div>`;
}
async function loadDashboard(){
  const [a, j, ab, st]=(await Promise.allSettled([get("/api/applications"), get("/api/jobs"), get("/api/auto_backup"), get("/api/storage")]))
    .map(x=>x.status==="fulfilled" ? x.value: {ok:false, error:String(x.reason||"error")});
  const alive=(a.apps||[]).filter(x=>!x.missing), n=alive.length;
  const prot=n ? Math.round(100*alive.filter(x=>x.protected).length/n): 0;
  const comp=n ? Math.round(100*alive.filter(x=>x.compliant).length/n): 0;
  const list=a.apps||[];
  $("#dbApps").innerHTML=donutSVG(prot, comp)+dnums("Protection", prot+"%", "Compliance", comp+"%");

  const on=!!ab.enabled;
  $("#dbPolicy").innerHTML=`<div style="display:flex;align-items:center;gap:10px;margin:4px 0 10px">${on ? stIc("ok"): stIc("na")}
      <span class="dbig" style="margin:0">${on ? "Enabled": "Disabled"}</span></div>
    <ul class="dlist">
      <li><span class="k">Frequency</span><span class="v">${on ? "Every "+Math.round(ab.interval_hours||24)+" h": "—"}</span></li>
      <li><span class="k">Retention</span><span class="v">${esc(abRetLabel(ab))}</span></li>
      <li><span class="k">Last run</span><span class="v">${ab.last_run ? esc(fmtAgo(ab.last_run))+" "+stIc(ab.last_ok?"ok":"ko"): "—"}</span></li>
      <li><span class="k">Next run</span><span class="v">${ab.next_due ? esc(new Date(ab.next_due*1000).toLocaleString()): "—"}</span></li>
      ${(ab.policies||[]).length ? `<li><span class="k">Other policies</span><span class="v">${esc((ab.policies||[]).map(p=>p.name).join(", "))}</span></li>`: ""}
    </ul>`;

  const keys=["hycu","nutanix","prismcentral"];
  const nConn=keys.filter(k=>conn[k] && conn[k].connected).length;
  const nConf=keys.filter(k=>conn[k] && conn[k].configured).length;
  $("#dbSources").innerHTML=donutSVG(Math.round(100*nConn/3), Math.round(100*nConf/3))+
    dnums("Connected", nConn+"/3", "Configured", nConf+"/3");
  $("#dbSources").style.cursor="pointer"; $("#dbSources").onclick=()=>openSources();
  $("#dbCluster").style.cursor="pointer"; $("#dbCluster").onclick=()=>openSources("cluster:"+ACTIVE_CID);

  $("#dbCluster").innerHTML=`<div class="dbig" style="font-size:21px;word-break:break-all">${esc(ctxInfo.context||"—")}</div>
    <div class="hint" style="margin:0 0 8px">${ctxInfo.workspace ? "Workspace "+esc(ctxInfo.workspace): "Active cluster"}</div>
    <ul class="dlist">
      <li><span class="k">kubectl</span><span class="v">${ctxInfo.kubectl_ok ? stIc("ok","Operational"): stIc("ko","Unavailable")}</span></li>
      <li><span class="k">Registered clusters</span><span class="v">${CLUSTERS.length}</span></li>
      <li><span class="k">Applications</span><span class="v">${n}</span></li>
      <li><span class="k">Namespaces</span><span class="v">${new Set(alive.map(x=>x.namespace||x.name)).size}</span></li>
      <li><span class="k">Namespace filter</span><span class="v">${a.filtered ? "Active": "None"}</span></li>
      <li><span class="k">Mode</span><span class="v">${dry() ? "Simulation": '<span class="ko">Real</span>'}</span></li>
    </ul>`;

  const roots=(st&&st.roots)||[];
  $("#dbStorage").innerHTML = roots.length? roots.map(x=>{
    if(!x.exists) return `<div class="hint">Folder missing: <code>${esc(x.path)}</code></div>`;
    const pct=x.disk_used_pct||0;
    const alert = pct>=90? ' <span class="bad" style="background:var(--red);color:#fff;border-radius:3px;padding:0 6px;font-size:11px">disk almost full</span>'
               : pct>=80? ' '+stIc("wn","Disk "+pct+"%"): "";
    return `<div style="margin-bottom:10px">
      <div class="hint" style="margin:0" title="${esc(x.path)}"><code>${esc(x.path.length>34? "…"+x.path.slice(-33):x.path)}</code>${alert}</div>
      ${storageBar(pct)}
      <div class="hint" style="margin:0">${pct}% used · ${esc(fmtBytes(x.disk_free))} free of ${esc(fmtBytes(x.disk_total))}</div>
      <ul class="dlist" style="margin-top:6px">
        <li><span class="k">Backups</span><span class="v">${x.backups_count||0} versions · ${esc(fmtBytes(x.backups_bytes))}</span></li>
        <li><span class="k">Audit log</span><span class="v">${esc(fmtBytes(x.audit_bytes))}</span></li>
        ${(st.quota_gb||0)>0? `<li><span class="k">Quota</span><span class="v">${(x.backups_bytes/1024/1024/1024).toFixed(1)} / ${st.quota_gb} Go${x.backups_bytes>st.quota_gb*1073741824? ' '+stIc("wn","Quota exceeded: oldest pruned at next pass"):''}</span></li>`:''}
      </ul></div>`;
  }).join(""): '<div class="tempty">—</div>';
  $("#dbStorage").innerHTML += (st.min_free_mb||0)>0? `<div class="hint" style="margin-top:2px">Guardrail: backup refused below ${st.min_free_mb} MB free.</div>`: "";
  $("#dbJobs").innerHTML=jobsChart(j.days)+`<div class="jcounts">${jobCounts(j)}</div>`;
  const last=(j.jobs||[]).slice(0, 5);
  $("#dbLast").innerHTML = last.length
    ? `<ul class="dlist">`+last.map(x=>{ const d=jobRowData(x);
        const ep=Date.parse(x.ts||"")/1000;
        return `<li><span class="k" style="display:flex;align-items:center;gap:8px;min-width:0">${stIc(d.st[0], d.st[1])}<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(d.lbl)}`+
               `${x.namespace ? ' <span style="color:var(--muted)">· '+d.app+'</span>': ''}</span></span>`+
               `<span class="v" style="font-weight:400;color:var(--muted);white-space:nowrap">${esc(isNaN(ep)?"":fmtAgo(ep))}</span></li>`; }).join("")+
      `</ul><div style="margin-top:8px"><a href="#" class="lnk" data-go="jobs">View all jobs</a></div>`
   : `<div class="tempty">No job recorded yet.</div>`;
  bindGo($("#dbLast"));
  $("#dbHealth").innerHTML = CLUSTERS.length
    ? `<ul class="dlist">`+CLUSTERS.map(c=>{
        const h=c.health;
        const ic = h? (h.ok? stIc("ok","Reachable"): stIc("ko",h.error||"")): stIc("na","Not checked yet");
        return `<li><span class="k" style="display:flex;align-items:center;gap:8px">${ic}<span>${esc(c.name)}</span></span>`+
               `<span class="v" style="font-weight:400;color:var(--muted)">${h? esc(fmtAgo(h.at)): "—"}</span></li>`;}).join("")+
      `</ul><div style="margin-top:8px"><a href="#" class="lnk" id="dbHealthLnk">Manage clusters</a></div>`
   : '<div class="tempty">—</div>';
  const hl=$("#dbHealthLnk"); if(hl) hl.onclick=e=>{ e.preventDefault(); openSources("cluster:"+ACTIVE_CID); };
}

// ============================ Assistant de restauration ============================
const RS_TITLE="Application restore";
const RS_KINDS={cloneapp:"Restore the whole application (copy)",
                inplace:"Restore storage in place",
                reattach:"Restore storage to new volumes",
                objects:"Restore configuration objects",
                dr:"DR restore (another cluster / context)"};
var rsWizPage="type", rsWizKind=null, rsWizAct=null, rsWizHtml="", rsTgtMode=null;
$("#rsAdvBody").append($("#rsCustomDirLbl"), $("#rsCustomDirWrap"));   // options avancées repliées
function rsKindFromState(){ return state.mode==="inplace" ? "inplace": (state.cloneSub==="cloneapp" ? "cloneapp": "reattach"); }
function rsSyncOpts(){ document.querySelectorAll("#rsPgType .opt").forEach(o=>o.classList.toggle("sel", o.dataset.kind===rsWizKind)); }
function rsSyncTgtOpts(){ document.querySelectorAll("#rsPgTarget .opt").forEach(o=>o.classList.toggle("sel", o.dataset.nsmode===rsTgtMode)); }
// “Next” depuis la page Type: le clone d'application passe d'abord par la page
// “cible du clone” (2 cartes); les autres types vont directement au formulaire.
function rsNextFromType(){
  if(rsWizKind==="cloneapp") return rsShowPage("target");
  if(rsWizKind==="objects") return objOpen();
  if(rsWizKind==="dr") return drOpen("dr");
  if(rsWizKind==="recover") return drOpen("recover", drRecoverNs);
  return rsToForm();
}
function rsTargetToForm(){
  if(!rsTgtMode) return;
  const b=document.querySelector('#rsCloneNsMode button[data-nsmode="'+rsTgtMode+'"]');
  if(b) b.click();                       // synchronise state.cloneNsMode + champs affichés
  return rsToForm();
}
document.querySelectorAll("#rsPgType .opt").forEach(o=>{
  o.onclick=()=>{ rsWizKind=o.dataset.kind; rsSyncOpts(); rsWizSync(); };
  o.ondblclick=()=>{ rsWizKind=o.dataset.kind; rsSyncOpts(); rsNextFromType(); };
});
document.querySelectorAll("#rsPgTarget .opt").forEach(o=>{
  o.onclick=()=>{ rsTgtMode=o.dataset.nsmode; rsSyncTgtOpts(); rsWizSync(); };
  o.ondblclick=()=>{ rsTgtMode=o.dataset.nsmode; rsSyncTgtOpts(); rsTargetToForm(); };
});
function rsShowPage(p){
  rsWizPage=p;
  if(p==="target"){ rsTgtMode=state.cloneNsMode||"same"; rsSyncTgtOpts(); }
  setRsStep(p==="type" ? 1: p==="plan" ? 3: 2);
  $("#rsPgType").style.display = p==="type" ? "block": "none";
  $("#rsPgTarget").style.display = p==="target" ? "block": "none";
  $("#rsPgObjects").style.display = p==="objects" ? "block": "none";
  $("#rsPgDr").style.display = p==="dr" ? "block": "none";
  $("#rsPgForm").style.display = p==="form" ? "block": "none";
  $("#rsPgPlan").style.display = p==="plan" ? "block": "none";
  // Retour vers le formulaire: re-masquer #rsPlan, sinon le prochain “Next”
  // (qui re-affiche le plan avec la MÊME valeur display:block) ne déclenche aucune
  // mutation -> l'observer ne bascule jamais sur la page 3 (bouton muet).
  if(p!=="plan") $("#rsPlan").style.display="none";
  $("#mRestoreTitle").innerHTML = p==="type" ? esc(RS_TITLE)
   : esc(RS_TITLE)+'<span class="sep">›</span>'+esc(RS_KINDS[rsWizKind]||"");
  $("#rsWizBack").style.display = p==="type" ? "none": "";
  const b=$("#mRestore .hm-body"); if(b) b.scrollTop=0;
  rsWizSync();
}
// Libellé “namespace › application” de l'assistant (application ciblée, ou namespace entier).
function rsAppLabel(){
  const a=state.app;
  if(!a || a.whole_ns) return esc(state.ns||"—");
  // Lien “tout le namespace”: élargit la restauration à toutes les applications du
  // namespace (visible sur chaque page de l'assistant, pas seulement la page Type).
  return esc(state.ns||"—")+' <span class="sep">›</span> '+esc(a.name)+
    (a.type==="stateless" ? ' <span class="badge b-pending">Stateless</span>': a.type==="stateful" ? ' <span class="badge b-bound">Stateful</span>': "")+
    ' <a href="#" class="rsWholeNs" style="margin-left:8px;font-weight:400;font-size:12px">whole namespace</a>';
}
document.addEventListener("click", e=>{ const a=e.target.closest && e.target.closest(".rsWholeNs, #rsWholeNs");
  if(a){ e.preventDefault(); rsTargetWholeNs(); } });
function openRestoreModal(ns, app){
  rsNewSession();
  ns = ns || state.ns || $("#rsNs").value; if(!ns) return;
  state.ns=ns; applyGlobalNs();
  // Application ciblée (page Applications): {name, type, pvcs, whole_ns}. Sans
  // application (whole namespace), l'assistant se comporte comme avant.
  state.app = (app && app.name && !app.whole_ns) ? {ns:ns, name:app.name, type:app.type, pvcs:app.pvcs||[], workloads:app.workloads||[], unassigned:!!app.unassigned}: null;
  rsWizKind=rsKindFromState(); rsSyncOpts();
  $("#rsWizApp").innerHTML=rsAppLabel();
  $("#rsWizCluster").innerHTML=`<b>${esc(ctxInfo.context||"—")}</b>`;
  ["#rsLog","#rsInplaceLog","#rsErr"].forEach(id=>$(id).innerHTML="");
  if($("#rsCustomDir").checked) $("#rsAdvWrap").open=true;
  rsRenderAppNote();
  openModal("mRestore");
  // Application STATELESS: les parcours de stockage n'ont pas de sens -> seules les cartes
  // “copie” (clone des workloads + dépendances) et “objets de configuration” restent,
  // la seconde présélectionnée (restauration = ré-appliquer ses objets).
  // Namespace entier sans aucun volume (que des applications stateless): même règle.
  const nsApps = apps.filter(a=>appNs(a)===ns && (a.cluster_id||ACTIVE_CID)===ACTIVE_CID);
  const nsNoVol = !state.app && nsApps.length>0 && nsApps.every(a=>!(a.pvcs||[]).length && !a.volumes);
  const sl = !!(state.app && state.app.type==="stateless") || nsNoVol;
  // La DR reste proposée: une sauvegarde stateless se restaure aussi sur un autre cluster.
  document.querySelectorAll('#rsPgType .opt').forEach(o=>{ o.style.display = (sl && (o.dataset.kind==="inplace"||o.dataset.kind==="reattach")) ? "none": ""; });
  if(sl){ rsWizKind="objects"; rsSyncOpts(); }
  rsShowPage("type");
}
// Clone d'une application STATELESS (aucun volume): le formulaire n'a pas de volumes à
// cocher; le serveur copie les workloads de l'application (+ dépendances).
function rsStatelessClone(){ return !!(state.app && state.app.type==="stateless" && rsWizKind==="cloneapp"); }
// Note “application ciblée” de l'assistant, avec le lien “tout le namespace”: quand
// une application fonctionnelle est découpée en plusieurs applications par ses étiquettes
// (ex. mariadb + wordpress), l'opérateur élargit la restauration à tout le namespace.
function rsRenderAppNote(){
  const note=$("#rsAppNote"); if(!note) return;
  note.style.display = state.app ? "block": "none";
  const link=`<div style="margin-top:6px"><a href="#" id="rsWholeNs">Rather restore <b>the whole namespace “${esc(state.ns||"")}”</b> (all its applications)</a></div>`;
  note.innerHTML = !state.app ? "": (state.app.type==="stateless"
    ? `Application <b>${esc(state.app.name)}</b>: <b>stateless</b> (no volume). Restoring it = re-applying its configuration objects (workloads, Services, ConfigMaps…) from a backup snapshot — the <b>“configuration objects”</b> path, preselected.`
   : `Application <b>${esc(state.app.name)}</b>: <b>stateful</b> — its volumes (${esc(state.app.pvcs.join(", ")||"—")}) will be preselected; the other volumes of the namespace stay unticked.`)+link;
}
function rsTargetWholeNs(){
  state.app=null; rsRenderAppNote();
  document.querySelectorAll('#rsPgType .opt').forEach(o=>o.style.display="");   // tous les parcours de nouveau
  $("#rsWizApp").innerHTML=rsAppLabel(); const oa=$("#objApp"); if(oa) oa.innerHTML=rsAppLabel();
  if(rsWizPage==="form"){ rsToForm().then(()=>{ rsAutoCheck=true; document.querySelectorAll(".rsChk").forEach(c=>c.checked=true); rebuildVolCfgs(); }); }
  else if(rsWizPage==="objects"){ objLoadList(); }
  rsWizSync();
}
async function rsToForm(){
  if(!rsWizKind) return;
  const k=rsWizKind, clk=sel=>{ const b=document.querySelector(sel); if(b) b.click(); };
  if(k==="inplace") clk('#rsMode button[data-mode="inplace"]');
  else { clk('#rsMode button[data-mode="clone"]');
         clk('#rsCloneSub button[data-sub="'+(k==="cloneapp" ? "cloneapp": "reattach")+'"]'); }
  rsShowPage("form");
  rsAutoCheck=true;
  $("#rsPlan").style.display="none";
  $("#rsAdvWrap").style.display="";
  if(rsStatelessClone()){
    state.ns=$("#rsNs").value||state.ns; state.backup_path=null; state.selected={};
    // Copie depuis le cluster vivant: ni volumes, ni panneau HYCU, ni choix de sauvegarde.
    hyPanelSeq++; $("#rsVolCfgs").innerHTML=""; const ha=$("#rsHyActions"); if(ha) ha.innerHTML="";
    $("#rsBackupSelWrap").style.display="none"; $("#rsAdvWrap").style.display="none";
    $("#rsPvcs").innerHTML=`<div class="note">Application <b>${esc(state.app.name)}</b>: <b>stateless</b>, no volume to restore. The copy recreates its workloads (${esc((state.app.workloads||[]).map(w=>w.kind+"/"+w.name).join(", ")||"—")}) and their dependencies from the cluster.</div>`;
    $("#rsConfig").style.display="none"; setRsStep(2); rsWizSync(); return;
  }
  $("#rsPvcs").innerHTML='<div class="hint"><span class="spin"></span>Loading volumes…</div>';
  await loadPvcs();
  rsWizSync();
}
// UNE action principale dans le pied de modale, qui relaie le bouton d'origine adapté
// à l'étape (clone HYCU groupé, restauration sur place, construction du plan, lancement).
function rsWizSync(){
  const go=$("#rsWizGo"); let lbl="Next", dis=false, act=null, src=null;
  $("#rsWizBack").style.display = (rsDone || rsWizPage==="type" || rsWizKind==="recover") ? "none": "";
  if(rsDone){ lbl="Verify the application →"; act=()=>gotoVerify(rsDoneTarget, true); }
  else if(rsWizPage==="type"){ dis=!rsWizKind; act=rsNextFromType; }
  else if(rsWizPage==="dr"){
    const n=document.querySelectorAll(".drRef").length, nNfs=document.querySelectorAll(".drNfs").length;
    const filled=[...document.querySelectorAll(".drRef")].filter(t=>t.value.trim()).length;
    // Réutilisation des volumes d'origine: aucun UUID requis (le serveur les déduit
    // de la sauvegarde). Sinon, tous les volumes doivent avoir une référence. Une
    // sauvegarde STATELESS (aucun volume, workloads dans l'instantané) se restaure sans volume.
    const needRefs = !drRecoverReuse();
    const b=drSel(), noVol = !n && !!(b && b.stateless);
    lbl=dry()? "Restore (simulation)": "Restore";
    dis=!drAllowed || (!n && !nNfs && !noVol) || (needRefs && filled<n) || drBusy || !$("#drTargetNs").value.trim();
    act=drRun;
  }
  else if(rsWizPage==="objects"){
    const n=document.querySelectorAll(".objChk:checked").length;
    if(objPhase==="pick"){ lbl="Preview differences"; dis=!n || objBusy; act=objToDiff; }
    else { lbl=dry()? "Apply (simulation)": "Apply"; dis=!n || objBusy; act=objApply; }
  }
  else if(rsWizPage==="target"){ dis=!rsTgtMode; act=rsTargetToForm; }
  else if(rsWizPage==="form"){
    const n=document.querySelectorAll(".rsChk:checked").length;
    const hyOn=!!(conn.hycu && conn.hycu.connected);
    if(isCloneApp()){
      // Clone d'application: lancement DIRECT depuis cette étape (une seule confirmation),
      // clones HYCU compris; en simulation, aperçu sans rien créer.
      const items=collectItems(), filled=items.length>0 && items.every(refOk);
      const batch=$("#hyBatchGo"), pending=!!batch && !filled;
      lbl = dry() ? "Check the copy": "Launch the application clone";
      dis = cloneBusy || (!rsStatelessClone() && (!n || (pending && batch.disabled)));
      act = cloneAppDirect;
    }
    else if(state.mode==="inplace" && hyOn){ src=$("#rsInplaceRun"); lbl="Restore in place"; }
    else {
      const items=collectItems(), filled=items.length>0 && items.every(refOk);
      const batch=$("#hyBatchGo");
      if(batch && !filled){ src=batch; lbl="Clone the VGs in HYCU →"; }
      else { dis=!n; act=()=>$("#rsPreview").click(); }
    }
    if(src){ dis=!n || src.disabled; act=()=>src.click(); }
  } else { src=$("#rsGo"); lbl=(src.textContent||"").trim() || "Launch"; dis=src.disabled || cloneBusy; act=()=>src.click(); }
  const busy = src && src.querySelector(".spin");
  const html = busy ? '<span class="spin"></span>'+esc((src.textContent||"").trim()): esc(lbl);
  if(html!==rsWizHtml){ go.innerHTML=html; rsWizHtml=html; }
  go.disabled=dis; rsWizAct=act;
  const live=!dry(), m=$("#rsWizMode");
  m.textContent = live ? "": "Simulation";       // la production est le mode normal: rien à signaler
  m.className="badge sim"; m.style.display = live ? "none": "";
}
$("#rsWizGo").onclick=()=>{ if(rsWizAct && !$("#rsWizGo").disabled) rsWizAct(); };
$("#rsWizBack").onclick=()=>{
  if(rsWizPage==="dr") return rsShowPage("type");
  if(rsWizPage==="objects"){
    if(objPhase==="diff"){ objPhase="pick"; $("#objDiffWrap").style.display="none"; $("#objPick").style.display="block"; $("#objLog").innerHTML=""; rsWizSync(); return; }
    return rsShowPage("type");
  }
  rsShowPage(rsWizPage==="plan" ? "form"
   : (rsWizPage==="form" && rsWizKind==="cloneapp") ? "target": "type");
};

// ----- DR restore: reprise sur CE cluster depuis une sauvegarde étrangère -----
var drAllowed=false, drBusy=false, drBackups=[], drMode="dr", drRecoverNs=null;
// Application SUPPRIMÉE du cluster: récupération sur le MÊME cluster/contexte —
// mêmes mécanismes que la page DR (sources depuis la sauvegarde seule), mais SANS
// la dérogation allow_dr_restore (le serveur vérifie que la sauvegarde est d'ici).
function openRecoverModal(ns){
  rsNewSession();
  state.ns=ns; state.app=null;         // la récupération recrée tout le namespace
  document.querySelectorAll('#rsPgType .opt').forEach(o=>{ o.style.display=""; });   // (masquées pour une app stateless)
  const note=$("#rsAppNote"); if(note){ note.style.display="none"; note.innerHTML=""; }
  rsWizKind="recover"; rsSyncOpts();   // kind dédié: “Retour” puis “Next” ne devient jamais une DR
  ["#rsLog","#rsInplaceLog","#rsErr"].forEach(id=>{ const e=$(id); if(e) e.innerHTML=""; });
  openModal("mRestore");
  drOpen("recover", ns);
}
$("#drOpenCfg").onclick=()=>{ closeModal("mRestore"); switchTab("settings"); };
async function drOpen(mode, recoverNs){
  drMode = mode==="recover" ? "recover": "dr";
  drRecoverNs = drMode==="recover" ? (recoverNs||null): null;
  // Rien de l'ouverture précédente ne doit rester cliquable pendant le chargement :
  // occupé + listes vidées, jusqu'au rendu des sauvegardes fraîches.
  drBusy=true; drBackups=[]; $("#drVols").innerHTML=""; $("#drBackupSel").innerHTML=""; $("#drTargetNs").value="";
  $("#drLog").innerHTML=""; $("#drErr").innerHTML="";
  $("#drSc").value="";                 // jamais de remap hérité d'un parcours précédent
  $("#drRefs").checked=true;
  rsShowPage("dr");
  if(drMode==="recover"){
    $("#mRestoreTitle").innerHTML=esc(RS_TITLE)+'<span class="sep">›</span>'+esc("Restore the deleted application “"+recoverNs+"”");
    $("#drWarnDr").style.display="none"; $("#drWarnRec").style.display="block";
    $("#drReuseWrap").style.display="block"; $("#drReuse").checked=true;
  } else {
    $("#drWarnDr").style.display="block"; $("#drWarnRec").style.display="none";
    $("#drReuseWrap").style.display="none";
  }
  $("#drCluster").textContent=ctxInfo.context||"—";
  $("#drClusterRec").textContent=ctxInfo.context||"—";
  const r=await get("/api/dr/backups");
  // Récupération même-cluster: pas de dérogation requise — le serveur re-vérifie.
  drAllowed = drMode==="recover" ? !!r.ok: !!(r.ok && r.allowed);
  $("#drGate").style.display = drAllowed? "none":"block";
  $("#drForm").style.display = drAllowed? "block":"none";
  if(!drAllowed){ drBusy=false; rsWizSync(); return; }
  drBackups=(r.backups||[]).filter(b=> drMode==="recover"
    ? (b.restorable_here && b.namespace===drRecoverNs): true);
  $("#drBackupSel").innerHTML = drBackups.length? drBackups.map((b,i)=>
    `<option value="${i}">${esc(b.cluster)}${b.context&&b.cluster_id==="local"?" ("+esc(b.context)+")":""} › ${esc(b.namespace)} › ${esc(b.timestamp)}${b.imported?" · S3 import":""}</option>`).join("")
   : '<option value="">(no backup)</option>';
  drBusy=false;
  drRenderVols();
  rsWizSync();
}
$("#drBackupSel").onchange=()=>drRenderVols();
function drSel(){ return drBackups[+$("#drBackupSel").value]||null; }
// Récupération: par défaut on réutilise les volumes d'origine (case cochée) -> aucune
// saisie. La grille d'UUID n'apparaît que pour la reprise d'activité, ou si l'humain a
// restauré les données sur de NOUVEAUX volumes (case décochée).
function drRecoverReuse(){ return drMode==="recover" && $("#drReuse").checked; }
function drRenderVols(){
  const b=drSel();
  $("#drTargetNs").value=b? b.namespace: "";
  // Honnêteté: sauvegarde sans instantané de ressources -> volumes uniquement.
  $("#drNoRes").style.display = (b && b.has_resources===false)? "block":"none";
  // Secrets de la sauvegarde: masqués (non recréés) ou chiffrés (coffre à déverrouiller).
  const sn=$("#drSecretsNote"), sm=b&&b.secrets;
  if(sn){ sn.style.display = (sm==="redacted"||sm==="encrypted") ? "block": "none";
    sn.innerHTML = sm==="redacted" ? "The <b>Secrets</b> of this backup are <b>redacted</b>: they will not be recreated (recreate them by hand after the restore)."
     : sm==="encrypted" ? "The <b>Secrets</b> of this backup are <b>encrypted</b> with the vault passphrase: unlock the vault (⚙ → Sources) before starting, otherwise they will not be recreated.": ""; }
  const refs=(b&&b.vol_refs)||{};
  // En récupération, chaque champ est PRÉ-REMPLI avec l'UUID d'origine (issu de la
  // sauvegarde): l'humain n'a rien à taper. En DR, les champs restent vides (nouveaux VG).
  const nfsOf=(b&&b.vol_nfs)||{};
  $("#drVols").innerHTML = b && b.volumes.length? b.volumes.map(v=> nfsOf[v]
    ? `<div class="drVol drNfs" data-pvc="${esc(v)}"><div class="drVolNm">${esc(v)} <span class="badge b-na">NAS</span></div>
       <div class="hint" style="margin:0">${esc("Same NFS export ("+nfsOf[v]+"): nothing to enter, the data stays on the NAS.")}</div></div>`
   : `<div class="drVol"><div class="drVolNm">${esc(v)}</div>
     <input type="text" class="drRef" data-pvc="${esc(v)}" spellcheck="false" autocomplete="off"
       value="${drMode==="recover"&&refs[v]?esc(refs[v]):""}"
       placeholder="${esc(drMode==="recover"?"Volume Group UUID (8-4-4-4-12)":"UUID of the VG restored/cloned on the target site (8-4-4-4-12)")}"></div>`).join("")
   : (b && b.stateless ? '<div class="note"><b>Stateless</b> backup (no volume): the workloads'+((b.apps||[]).length?' ('+esc((b.apps||[]).join(", "))+')':'')+' and their dependencies will be recreated from the snapshot.</div>'
                       : '<div class="hint">No volume in this backup.</div>');
  document.querySelectorAll(".drRef").forEach(t=>t.oninput=rsWizSync);
  drSyncReuse();
}
// Bascule d'affichage de la grille selon “réutiliser les volumes d'origine”.
function drSyncReuse(){
  const reuse=drRecoverReuse(), bsel=drSel(), stateless=!!(bsel && bsel.stateless);
  // Sauvegarde STATELESS: aucun champ de volume (StorageClass, réutilisation, UUID, HYCU).
  $("#drScRow").style.display = stateless ? "none": "";
  $("#drReuseWrap").style.display = (drMode==="recover" && !stateless) ? "block": "none";
  $("#drVols").style.display = (reuse && !stateless)? "none":"block";
  $("#drVolsLabel").style.display = stateless ? "none": ((drMode==="recover")? (reuse?"none":"block"): "block");
  if(drMode==="recover") $("#drVolsLabel").textContent="New volumes — paste the ID (UUID) provided by HYCU";
  else $("#drVolsLabel").textContent="Volumes — paste the UUID of the VG restored/cloned on the target site";
  // Bouton “auto HYCU”: seulement quand la grille est visible ET HYCU + Prism connectés.
  const autoOk = !reuse && !stateless && !rsDone && (conn.hycu&&conn.hycu.connected)
                 && ((conn.prismcentral&&conn.prismcentral.connected)||(conn.nutanix&&conn.nutanix.connected));
  $("#drAutoWrap").style.display = autoOk? "block":"none";
  rsWizSync();
}
$("#drReuse").onchange=drSyncReuse;
// Auto-provisionnement: HYCU clone les VG et l'outil découvre leurs nouveaux UUID,
// qu'il inscrit dans la grille (aucune saisie). Simulation = plan seulement.
$("#drAuto").onclick=async()=>{
  const b=drSel(); if(!b) return;
  const refs=(b&&b.vol_refs)||{}, hy=(b&&b.vol_hycu)||{}, names=(b&&b.vol_names)||{};
  // Source pour HYCU = l'identité HYCU du VG (contrat) si disponible, sinon l'UUID Nutanix ;
  // le nom du VG aide à retrouver un VG SUPPRIMÉ du cluster dans le catalogue HYCU.
  const volumes=[...document.querySelectorAll(".drRef")].map(t=>({pvc:t.dataset.pvc,
    source_vg_uuid:hy[t.dataset.pvc]||refs[t.dataset.pvc]||"", vg_name:names[t.dataset.pvc]||""}));
  if(!volumes.length || volumes.some(v=>!v.source_vg_uuid)){
    $("#drErr").innerHTML=errBox("Source VG UUID missing from the backup: automation not possible, enter the UUIDs manually."); return; }
  if(!dry() && !(await confirmDanger({title:"Confirm the HYCU clones", lines:[
      "Clone in HYCU <b>"+volumes.length+"</b> Volume Group(s) (new VGs are created)?",
      "The new IDs will be filled into the grid automatically."]}))) return;
  const btn=$("#drAuto"); btn.disabled=true; drBusy=true; rsWizSync();
  $("#drErr").innerHTML=""; $("#drLog").innerHTML='<div class="hint"><span class="spin"></span>HYCU: creating the volumes…</div>';
  try{
    const r=await post("/api/hycu/provision_clone", {volumes, dry:dry()});
    if(!r.ok){ $("#drErr").innerHTML=errBox(r.error); $("#drLog").innerHTML=renderLog(r.log||[]); return; }
    if(!r.dry){ (r.items||[]).forEach(it=>{ const el=document.querySelector('.drRef[data-pvc="'+(window.CSS&&CSS.escape?CSS.escape(it.pvc):it.pvc)+'"]'); if(el && it.new_ref) el.value=it.new_ref; }); }
    $("#drLog").innerHTML=renderLog(r.log||[]);
  } finally { btn.disabled=false; drBusy=false; rsWizSync(); }
};
$("#drTargetNs").oninput=()=>rsWizSync();
async function drRun(){
  const b=drSel(); if(!b) return;
  // Réutilisation des volumes d'origine: on n'envoie PAS d'UUID, le serveur le déduit
  // de la sauvegarde (source de vérité). Sinon on transmet ce que l'humain a saisi.
  const reuse=drRecoverReuse();
  const items=[...document.querySelectorAll(".drRef")].map(t=>({pvc:t.dataset.pvc, new_ref:reuse?"":t.value.trim()}))
    .concat([...document.querySelectorAll(".drNfs")].map(d=>({pvc:d.dataset.pvc, new_ref:""})));   // NAS: même export
  const live=!dry();
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res=await confirmDanger({title:(drMode==="recover"?"Confirm the deleted application restore":"Confirm the DR restore"), requireText:needCtx, lines:[
      "Source backup: <b>"+esc(b.cluster)+" › "+esc(b.namespace)+" › "+esc(b.timestamp)+"</b>",
      "TARGET cluster: <b>"+esc(ctxInfo.context||"?")+"</b> · target namespace: <b>"+esc($("#drTargetNs").value)+"</b>",
      drMode==="recover"
        ? "The application will be RECREATED on this cluster from the backup (namespace, PV/PVC, workloads, non-redacted dependencies)."
       : "The cross-cluster guard is LIFTED for this operation: the application will be recreated on this cluster from the backup (PV/PVC, workloads, non-redacted dependencies).",
      ...((drMode==="recover" && !b.stateless && drRecoverReuse() && conn.hycu && conn.hycu.connected)
        ? ["If an original volume has disappeared from the cluster, HYCU will restore it automatically before recreating."]: [])]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  drBusy=true; rsWizSync();
  $("#drLog").innerHTML='<div class="hint"><span class="spin"></span>'+(drMode==="recover"?"Restoring the application…":"DR restore…")+'</div>';
  const body={namespace:b.namespace, target_namespace:$("#drTargetNs").value.trim(),
              backup_path:b.path, items, dry:dry(),
              dr_storageclass:$("#drSc").value.trim(), clone_refs:$("#drRefs").checked};
  if(drMode==="recover") body.from_backup_only=true; else body.dr_restore=true;
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const sess=rsSession;
  const r=await runOp("/api/clone_app", body, log=>{ if(sess===rsSession) $("#drLog").innerHTML=renderLog(log); });
  if(sess!==rsSession) return;
  drBusy=false; rsWizSync();
  const reprot = b.stateless ? "": " Remember to re-protect its Volume Groups in HYCU.";
  const done = (drMode==="recover" ? "Application restore finished.": "DR restore finished.") + reprot;
  const head = r.ok? (r.dry? '<div class="note">Simulation — sequence that would be run.</div>'
                          : '<div class="note">'+done+'</div>')
                  : errBox(r.error || "Some steps failed — see details.");
  $("#drLog").innerHTML=head+cloneWarnings(r.warnings)+renderLog(r.log);
  if(r.ok && !r.dry) rsFinish(body.target_namespace || b.namespace, false, sess, true);
}

// ----- Restauration guidée des OBJETS de configuration (resources.json) -----
var objItems=[], objPhase="pick", objBusy=false, objBackups=[];
function objBody_(){ return {namespace:$("#rsNs").value||state.ns,
  backup_path:($("#objBackupSel").value||null), backup_root:state.backup_root||null,
  app:(state.app && !state.app.unassigned) ? state.app.name: null}; }
async function objOpen(){
  objPhase="pick"; objBusy=true; objItems=[];
  $("#objApp").innerHTML=rsAppLabel();
  $("#objErr").innerHTML=""; $("#objLog").innerHTML=""; $("#objDiffWrap").style.display="none";
  $("#objPick").style.display="block";
  $("#objBody").innerHTML='<tr><td colspan="4" class="tempty"><span class="spin"></span></td></tr>';
  rsShowPage("objects");
  const ns=state.ns||$("#rsNs").value;
  const b=await get("/api/backups?ns="+encodeURIComponent(ns)+(state.backup_root?("&root="+encodeURIComponent(state.backup_root)):""));
  objBackups=(b.backups||[]);
  $("#objBackupSel").innerHTML=objBackups.map(x=>`<option value="${esc(x.path)}">${esc(x.timestamp)} — ${((x.index||{}).volumes||[]).length} volume(s)${(x.index||{}).resources_count!=null?(" · "+(x.index||{}).resources_count+" objects"):""}</option>`).join("")
    || '<option value="">(no backup)</option>';
  await objLoadList();
}
$("#objBackupSel").onchange=()=>objLoadList();
async function objLoadList(){
  objBusy=true;
  // Nouvelle liste = retour à la sélection: jamais appliquer des objets d'une autre
  // sauvegarde que celle dont les différences sont affichées.
  objPhase="pick"; $("#objDiffWrap").style.display="none"; $("#objPick").style.display="block"; setRsStep(2);
  rsWizSync();
  $("#objErr").innerHTML=""; $("#objLog").innerHTML="";
  if(!$("#objBackupSel").value){
    $("#objBody").innerHTML='<tr><td colspan="4" class="tempty">No backup for this namespace — run a backup first (Applications → Back up).</td></tr>';
    objItems=[]; objBusy=false; rsWizSync(); return;
  }
  const r=await post("/api/objects/list", objBody_());
  objBusy=false;
  if(!r.ok){ $("#objBody").innerHTML=""; $("#objErr").innerHTML=errBox(r.error); objItems=[]; rsWizSync(); return; }
  objItems=r.items||[];
  // Application ciblée: ses objets sont marqués (in_app) et PRÉCOCHÉS; les objets des
  // autres applications du namespace sont masqués par défaut (case “seulement…”).
  const appOn = !!(r.app);
  $("#objOnlyAppWrap").style.display = appOn ? "": "none";
  $("#objInfo").textContent="("+objItems.length+" object(s) in the snapshot"+(appOn?(" · "+(r.app_count||0)+" of the application “"+r.app+"”"):"")+")";
  $("#objBody").innerHTML=objItems.length? objItems.map(o=>`<tr class="clk${o.redacted?'':' '}${appOn&&!o.in_app?' objOther':''}" data-i="${o.i}">
     <td class="cb"><input type="checkbox" class="objChk" data-i="${o.i}" ${o.redacted?"disabled":""} ${appOn&&o.in_app&&!o.redacted?"checked":""}></td>
     <td>${esc(o.kind)}</td><td style="color:var(--strong);font-weight:500">${esc(o.name)}</td>
     <td>${o.encrypted?'<span class="badge b-pending">Secret encrypted — unlock the vault</span>':o.redacted?'<span class="badge b-pending">Secret redacted — not restorable</span>':(appOn&&!o.in_app?'<span class="hint">other application / shared</span>':"")}</td></tr>`).join("")
   : '<tr><td colspan="4" class="tempty">Empty snapshot.</td></tr>';
  document.querySelectorAll("#objBody tr.clk").forEach(tr=>tr.onclick=e=>{
    if(e.target.classList.contains("objChk")) return rsWizSync();
    const c=tr.querySelector(".objChk"); if(c && !c.disabled){ c.checked=!c.checked; rsWizSync(); } });
  document.querySelectorAll(".objChk").forEach(c=>c.onchange=rsWizSync);
  $("#objAll").checked=false; objSyncOnlyApp(); rsWizSync();
}
function objSyncOnlyApp(){
  const only = $("#objOnlyAppWrap").style.display!=="none" && $("#objOnlyApp").checked;
  document.querySelectorAll("#objBody tr.objOther").forEach(tr=>{ tr.style.display = only ? "none": "";
    if(only){ const c=tr.querySelector(".objChk"); if(c) c.checked=false; } });
}
$("#objOnlyApp").onchange=()=>{ objSyncOnlyApp(); rsWizSync(); };
$("#objAll").onchange=()=>{ const on=$("#objAll").checked;
  document.querySelectorAll("#objBody tr").forEach(tr=>{ if(tr.style.display==="none") return;
    const c=tr.querySelector(".objChk:not([disabled])"); if(c) c.checked=on; }); rsWizSync(); };
function objSelIdx(){ return [...document.querySelectorAll(".objChk:checked")].map(c=>+c.dataset.i); }
async function objToDiff(){
  objBusy=true; rsWizSync();
  $("#objErr").innerHTML="";
  $("#objDiff").innerHTML='<div class="hint"><span class="spin"></span>Comparing with the live state…</div>';
  $("#objDiffWrap").style.display="block"; setRsStep(3);
  const r=await post("/api/objects/diff", Object.assign(objBody_(), {indexes:objSelIdx()}));
  objBusy=false;
  if(!r.ok){ $("#objDiffWrap").style.display="none"; $("#objErr").innerHTML=errBox(r.error); rsWizSync(); return; }
  const ST={identical:["ok","Identical to live — apply is a no-op"], differs:["wn","Differs from live"],
            absent:["run","Absent from live — will be (re)created"], error:["ko","Cannot read live state"],
            redacted:["ko","Secret redacted"]};
  $("#objDiff").innerHTML=(r.results||[]).map(x=>{
    const st=ST[x.status]||["na",x.status];
    const body = x.status==="differs" ? `<pre class="box" style="margin:6px 0 0;max-height:260px;overflow:auto">${esc(x.diff)}</pre>`
     : (x.error? `<div class="hint" style="color:var(--red)">${esc(x.error)}</div>`: "");
    return `<div class="repl" style="margin-bottom:10px"><div class="nm" style="display:flex;gap:10px;align-items:center">${stIc(st[0],st[1])}<b>${esc(x.kind)}/${esc(x.name)}</b><span class="hint">${esc(st[1])}</span></div>${body}</div>`;
  }).join("") || '<div class="hint">Nothing to compare.</div>';
  $("#objPick").style.display="none"; objPhase="diff"; rsWizSync();
}
async function objApply(){
  const live=!dry();
  let confirmedCtx="";
  if(live){
    const needCtx = ctxInfo.require_confirm ? (ctxInfo.context||""): null;
    const res=await confirmDanger({title:"Confirm the object restore", requireText:needCtx, lines:[
      "Namespace: <b>"+esc($("#rsNs").value||state.ns||"?")+"</b>",
      "Target cluster: <b>"+esc(ctxInfo.context||"?")+"</b>",
      "<b>"+objSelIdx().length+"</b> configuration object(s) will be OVERWRITTEN by the backup version (kubectl apply). Volumes and data are untouched."]});
    if(!res) return;
    if(typeof res==="string") confirmedCtx=res;
  }
  objBusy=true; rsWizSync();
  $("#objLog").innerHTML='<div class="hint"><span class="spin"></span>Applying…</div>';
  const body=Object.assign(objBody_(), {indexes:objSelIdx(), dry:dry()});
  if(live && ctxInfo.require_confirm) body.confirm_context=confirmedCtx;
  const sess=rsSession;
  const r=await post("/api/objects/restore", body);
  if(sess!==rsSession) return;
  objBusy=false; rsWizSync();
  const head = r.ok? (r.dry? '<div class="warnbox">Simulation — commands that would be run.</div>'
                          : `<div class="note">${"Object restore finished: "+r.applied+" object(s) applied"}${r.skipped?(" · "+r.skipped+" skipped"):""}.</div>`)
                  : errBox(r.error);
  $("#objLog").innerHTML=head+renderLog(r.log);
  if(r.ok && !r.dry) rsFinish(body.namespace, !!r.skipped, sess);
}
setInterval(()=>{ if($("#mRestore").style.display!=="none") rsWizSync(); }, 300);

