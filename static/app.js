const state = {page:1,pageSize:10,total:0,lastLogId:0,items:[],settings:null,refreshing:false,polling:false,again:false,selected:new Set(),deleting:false};
const $ = id => document.getElementById(id);
const labels = {active:'正常',missing:'未登录',pending:'认证中',queued:'排队中',deleted:'账号已删除',error:'认证失败',invalid:'认证失效',unavailable:'额度或上游不可用',disabled:'已停用',paused:'已暂停'};
function esc(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function formatTime(value){if(!value)return '—';const date=new Date(value);return Number.isNaN(date.getTime())?'—':date.toLocaleString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});}
function toast(message,error=false){const element=$('toast');element.textContent=message;element.className='toast'+(error?' error':'');element.hidden=false;clearTimeout(toast.timer);toast.timer=setTimeout(()=>{element.hidden=true;},4000);}
function loading(active,message='正在建立会话并读取凭据，请稍候…'){$('connectDetail').textContent=message;$('connectOverlay').hidden=!active;$('tableScroll').setAttribute('aria-busy',String(active));}
function connection(status){const text={connecting:'正在连接 CPA',connected:'CPA 已连接',error:'CPA 连接失败'}[status];$('connectionDot').className='dot '+status;$('sideDot').className='dot '+status;$('connectionText').textContent=text;$('sideStatus').textContent=text;}
async function api(url,options={}){const response=await fetch(url,{cache:'no-store',...options,headers:{'X-CPA-Request':'1',...options.headers}});let data;try{data=await response.json();}catch{throw new Error('服务返回内容无效，请检查 Python 服务日志');}if(response.status===401){location.replace('/login');throw new Error('登录已过期，请重新登录');}if(!response.ok)throw new Error(data.error||`请求失败（${response.status}）`);return data;}
function resetRemaining(value){const seconds=Math.floor((new Date(value).getTime()-Date.now())/1000);if(!Number.isFinite(seconds))return '';if(seconds<=0)return '已到重置时间';if(seconds>=86400)return `${Math.floor(seconds/86400)} 天后重置`;if(seconds>=3600)return `${Math.floor(seconds/3600)} 小时后重置`;return `${Math.max(1,Math.floor(seconds/60))} 分钟后重置`;}
function resetHtml(row){const items=row.reset_times;let html=items?.length?items.map(item=>`<div class="date">${esc(item.label)} ${formatTime(item.reset_at)}</div><div class="subtle">${esc(resetRemaining(item.reset_at))}</div>`).join(''):'<div class="date">—</div>';if(row.quota_loading)html+='<div class="subtle">正在查询额度…</div>';else if(row.quota_error)html+=`<div class="subtle" title="${esc(row.quota_error)}">${esc(row.quota_error)}${items?.length?' · 历史观测':''}</div>`;else if(!items?.length)html+='<div class="subtle">暂无重置时间</div>';return html;}
function quotaHtml(items,observed){if(!items?.length)return '<span class="subtle">暂无额度观测</span>';return `<div class="quota" title="${esc('CPA 观测时间：'+formatTime(observed))}">`+items.map(item=>{const used=Number(item.used_percent);const cls=used>=95?'full':used>=80?'high':'';return `<div class="quota-line" title="${esc('重置：'+formatTime(item.reset_at))}"><span>${esc(item.label)}</span><div class="progress"><i class="${cls}" style="width:${used}%"></i></div><strong>${used.toFixed(0)}%</strong></div>`;}).join('')+'</div>';}
function render(data){
  state.items=data.items;state.total=data.total;state.page=data.page;
  const counts=data.counts||{};
  $('statTotal').textContent=data.configured_total;$('statActive').textContent=counts.active||0;
  $('statPending').textContent=(counts.missing||0)+(counts.invalid||0);$('statRunning').textContent=counts.pending||0;
  $('queued').textContent=counts.queued||0;$('navCount').textContent=data.configured_total;$('listCount').textContent=state.total;
  $('rows').innerHTML=data.items.length?data.items.map(item=>{
    const status=Object.hasOwn(labels,item.status)?item.status:'unknown';
    const planClass=String(item.plan_type||'').toLowerCase()==='free'?'free':String(item.plan_type||'').toLowerCase().startsWith('pro')?'pro':'';
    const busy=['pending','queued'].includes(status);
    return `<tr><td><label class="serial-cell"><input type="checkbox" data-select="${esc(item.email)}" aria-label="选择 ${esc(item.email)}" ${state.selected.has(item.email)?'checked':''}><span class="serial-number">${item.serial}</span></label></td><td><div class="account-title">${esc(item.email)}</div><div class="account-sub" title="${esc(item.credential_name||'')}">${esc(item.credential_name||'未生成认证文件')}</div></td><td><span class="status ${status}"><i></i>${esc(labels[status]||'未知')}</span></td><td><span class="plan ${planClass}">${esc(item.plan_type||'—')}</span></td><td>${resetHtml(item)}</td><td>${quotaHtml(item.quota,item.quota_observed_at)}</td><td><div class="row-actions"><button class="row-action" data-login="${esc(item.email)}" ${busy?'disabled':''}>${busy?'处理中':'重新认证'} <svg style="width:11px;height:11px"><use href="#i-arrow"/></svg></button><button class="row-action danger" data-delete="${esc(item.email)}" ${busy||state.deleting?'disabled':''}>删除</button></div></td></tr>`;
  }).join(''):'<tr><td colspan="7"><div class="table-empty">没有匹配的配置账号</div></td></tr>';
  $('pageInfo').textContent=state.total?`共 ${state.total} 条 · 当前 ${(state.page-1)*state.pageSize+1}–${Math.min(state.page*state.pageSize,state.total)} 条`:'共 0 条';
  $('pageNumber').textContent=`${state.page} / ${Math.max(1,Math.ceil(state.total/state.pageSize))}`;
  $('prevBtn').disabled=state.page<=1;$('nextBtn').disabled=!data.has_more;
  renderSelection();
  clearTimeout(state.quotaTimer);if(data.items.some(item=>item.quota_loading))state.quotaTimer=setTimeout(()=>refresh(),1500);
}
async function refresh(showLoader=false){
  if(state.refreshing){state.again=true;return;}
  state.refreshing=true;
  if(showLoader){loading(true);connection('connecting');}
  $('refreshBtn').disabled=true;
  try{
    const query=new URLSearchParams({page:state.page,page_size:state.pageSize,q:$('search').value.trim(),status:$('statusFilter').value});
    render(await api('/api/accounts?'+query));
    connection('connected');$('syncTime').textContent='上次同步 '+new Date().toLocaleTimeString('zh-CN');$('tableError').hidden=true;
  }catch(error){
    connection('error');$('tableError').textContent=error.message;$('tableError').hidden=false;
    if(!state.items.length)$('rows').innerHTML='<tr><td colspan="7"><div class="table-empty">连接 CPA 失败，请检查配置后点击刷新</div></td></tr>';
    if(showLoader)toast(error.message,true);
  }finally{
    state.refreshing=false;$('refreshBtn').disabled=false;if(showLoader)loading(false);
    if(state.again){state.again=false;refresh();}
  }
}
function renderSettings(settings){
  state.settings=settings;const enabled=!!settings.auto_reauth;
  $('autoToggle').setAttribute('aria-checked',String(enabled));$('autoBadge').textContent=enabled?'已开启':'已关闭';$('autoBadge').className='badge '+(enabled?'':'neutral');
  $('autoInterval').textContent=`每 ${settings.auto_reauth_interval} 秒检测`;$('concurrency').textContent=settings.auth_concurrency;
  $('modeText').textContent=settings.transport==='browser'?'浏览器会话连接':'直连 HTTP';$('modeText').title=settings.cpa_host;
}
async function toggleAuto(){
  const enabled=$('autoToggle').getAttribute('aria-checked')!=='true';$('autoToggle').disabled=true;
  try{renderSettings(await api('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({auto_reauth:enabled})}));toast(enabled?'自动重认证已开启，后台将定时检查所有配置账号':'自动重认证已关闭，已启动的任务将继续完成');}
  catch(error){toast(error.message,true);}finally{$('autoToggle').disabled=false;}
}
async function login(email){
  try{await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});toast('认证任务已加入队列');refresh();}
  catch(error){toast(error.message,true);}
}
async function batch(){
  $('batchBtn').disabled=true;loading(true,'正在检查所有配置账号，准备批量认证…');
  try{const data=await api('/api/login-all',{method:'POST'});toast(data.started?`已加入 ${data.started} 个账号，并发 ${data.concurrency}，跳过 ${data.skipped.length} 个`:'全部账号均已认证或已跳过，无待处理任务');refresh();}
  catch(error){toast(error.message,true);}finally{$('batchBtn').disabled=false;loading(false);}
}
function renderSelection(){const count=state.items.filter(item=>state.selected.has(item.email)).length;$('selectPage').checked=state.items.length>0&&count===state.items.length;$('selectPage').indeterminate=count>0&&count<state.items.length;$('selectPage').disabled=!state.items.length||state.deleting;$('selectionCount').textContent=`已选择 ${state.selected.size} 个账号`;$('deleteBtn').disabled=!state.selected.size||state.deleting;$('clearSelectionBtn').disabled=!state.selected.size||state.deleting;$('selectAllBtn').disabled=!state.total||state.deleting;for(const input of $('rows').querySelectorAll('[data-select]')){input.checked=state.selected.has(input.dataset.select);input.disabled=state.deleting;}}
function clearSelection(){state.selected.clear();renderSelection();}
async function selectAll(){const query=new URLSearchParams({selection:'all',q:$('search').value.trim(),status:$('statusFilter').value});$('selectAllBtn').disabled=true;try{const data=await api('/api/accounts?'+query);state.selected=new Set(data.emails);renderSelection();toast(`已选择筛选结果中的 ${data.emails.length} 个账号`);}catch(error){toast(error.message,true);}finally{renderSelection();}}
async function removeCredentials(emails){
  if(state.deleting||!emails.length)return;
  const target=emails.length===1?emails[0]:`所选 ${emails.length} 个账号`;
  if(!window.confirm(`删除 ${target} 在 CPA 中的对应凭证？账号配置会保留，删除后暂停自动重认证，可手动认证恢复。`))return;
  state.deleting=true;renderSelection();loading(true,`正在删除 ${emails.length} 个账号对应的 CPA 凭证…`);
  try{const data=await api('/api/delete-all',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({emails})});for(const email of data.processed_emails||[])state.selected.delete(email);toast(`删除 ${data.deleted.length} 个凭证，${data.missing?.length||0} 个账号无凭证，失败 ${data.failed.length} 个`,data.failed.length>0);await refresh();}
  catch(error){toast(error.message,true);}finally{state.deleting=false;renderSelection();loading(false);}
}
async function pollLogs(){
  if(state.polling)return;state.polling=true;
  try{
    let data=await api('/api/logs?since='+state.lastLogId);
    if(data.last_id<state.lastLogId){state.lastLogId=0;data=await api('/api/logs?since=0');}
    state.lastLogId=data.last_id;
    if(data.logs.length)$('logs').querySelector('.log-placeholder')?.remove();
    for(const entry of data.logs){const line=document.createElement('div');line.className='log-line'+(entry.level==='error'?' error':'');const time=document.createElement('span');time.className='log-time';time.textContent=entry.time;const message=document.createElement('span');message.className='log-message';message.textContent=entry.message;line.append(time,message);$('logs').append(line);}
    while($('logs').children.length>500)$('logs').firstElementChild.remove();
    if($('followLogs').checked)$('logs').scrollTop=$('logs').scrollHeight;
  }catch{}finally{state.polling=false;}
}
function closeDialog(){$('addDialog').close();}
async function saveAccount(event){
  event.preventDefault();$('saveBtn').disabled=true;
  try{await api('/api/accounts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('email').value.trim(),password:$('password').value,totp_secret:$('totp').value.trim()})});toast('账号已保存');event.target.reset();closeDialog();state.page=1;refresh(true);}
  catch(error){toast(error.message,true);}finally{$('saveBtn').disabled=false;}
}
$('refreshBtn').onclick=()=>refresh(true);$('batchBtn').onclick=batch;$('deleteBtn').onclick=()=>removeCredentials([...state.selected]);$('autoToggle').onclick=toggleAuto;
$('selectPage').onchange=()=>{for(const item of state.items){if($('selectPage').checked)state.selected.add(item.email);else state.selected.delete(item.email);}renderSelection();};$('selectAllBtn').onclick=selectAll;$('clearSelectionBtn').onclick=clearSelection;
$('logoutBtn').onclick=async()=>{try{await api('/api/auth/logout',{method:'POST'});location.replace('/login');}catch(error){toast(error.message,true);}};
$('pageSize').onchange=()=>{state.pageSize=Number($('pageSize').value);state.page=1;refresh(true);};
$('prevBtn').onclick=()=>{if(state.page>1){state.page--;refresh(true);}};$('nextBtn').onclick=()=>{if(state.page*state.pageSize<state.total){state.page++;refresh(true);}};
let searchTimer;$('search').oninput=()=>{clearSelection();clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.page=1;refresh();},300);};$('statusFilter').onchange=()=>{clearSelection();state.page=1;refresh(true);};
$('rows').onchange=event=>{const input=event.target.closest('[data-select]');if(input){if(input.checked)state.selected.add(input.dataset.select);else state.selected.delete(input.dataset.select);renderSelection();}};
$('rows').onclick=event=>{const button=event.target.closest('[data-login]');if(button&&!button.disabled)login(button.dataset.login);const remove=event.target.closest('[data-delete]');if(remove&&!remove.disabled)removeCredentials([remove.dataset.delete]);};
$('clearLogs').onclick=()=>{$('logs').replaceChildren();};$('addBtn').onclick=()=>$('addDialog').showModal();$('closeDialog').onclick=closeDialog;$('cancelAdd').onclick=closeDialog;$('accountForm').onsubmit=saveAccount;
for(const anchor of document.querySelectorAll('.nav-item'))anchor.onclick=()=>{document.querySelector('.nav-item.selected')?.classList.remove('selected');anchor.classList.add('selected');};
async function initialize(){try{renderSettings(await api('/api/settings'));}catch(error){toast('读取设置失败：'+error.message,true);}await refresh(true);}
initialize();pollLogs();setInterval(pollLogs,1500);setInterval(()=>refresh(),10000);
