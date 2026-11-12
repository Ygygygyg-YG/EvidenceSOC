'use strict';
// Isolated browser acceptance data. Never imported into the application or its production bundle.
const end = '2026-11-04T05:30:00.000Z';
const alerts = [
  ['AL-P2-001','服务账户异常登录后访问敏感共享目录','high','awaiting_approval'],
  ['AL-P2-002','外部来源重复尝试远程身份认证','critical','analyzing'],
  ['AL-P2-003','非常规时段执行远程管理脚本','medium','manual_review'],
  ['AL-P2-004','Web 请求包含可疑的 SQL 注入特征','high','completed'],
  ['AL-P2-005','敏感目录访问频次出现短时上升','medium','analyzing'],
  ['AL-P2-006','应用服务出现异常身份验证记录','low','manual_review'],
].map(([alert_id,title,severity,status],i)=>({alert_id,title,severity,status,created_at:new Date(Date.parse(end)-(i+1)*420000).toISOString(),event_ids:[`EVENT-P2-${i+1}`]}));
const health = {checked_at:end,postgresql_status:'ok',opensearch_status:null,is_stale:false,sources:[
  {source:'nginx',last_ingested_at:'2026-11-04T05:29:18.000Z',ingestion_lag_seconds:42,status:'ok',is_stale:false},
  {source:'Windows Security',last_ingested_at:'2026-11-04T05:26:00.000Z',ingestion_lag_seconds:240,status:null,is_stale:null},
]};
function summary(window='24h') {
  const duration={'1h':3600000,'24h':86400000,'7d':604800000}[window] || 86400000;
  const from=Date.parse(end)-duration;
  const totals=[8,12,7,17,11,13], high=[3,4,2,6,3,5];
  return {window,execution_mode:'rules',time_from:new Date(from).toISOString(),time_to:end,generated_at:end,
    metrics:{alerts_in_window:68,high_risk_incidents:5,running_investigations:3,pending_response_plans:2},
    alert_trend:totals.map((total,i)=>({bucket_start:new Date(from+duration*i/6).toISOString(),bucket_end:new Date(from+duration*(i+1)/6).toISOString(),total,high_risk:high[i]})),
    incident_status_distribution:[{status:'awaiting_approval',count:2},{status:'analyzing',count:3},{status:'manual_review',count:4},{status:'completed',count:18}],
    recent_alerts:alerts.slice(0,4),recent_activity:[
      {event:'approval.required',occurred_at:'2026-11-04T05:24:00.000Z',incident_id:'IN-P2-001',investigation_id:'IV-P2-001'},
      {event:'investigation.started',occurred_at:'2026-11-04T05:18:00.000Z',incident_id:'IN-P2-002',investigation_id:'IV-P2-002'},
      {event:'validation.completed',occurred_at:'2026-11-04T05:08:00.000Z',incident_id:'IN-P2-004',investigation_id:'IV-P2-004'},
    ],source_health:health};
}
const incidents = alerts.slice(0,4).map((a,i)=>({incident_id:`IN-P2-00${i+1}`,investigation_id:`IV-P2-00${i+1}`,alert_id:a.alert_id,alert_title:a.title,severity:a.severity,status:a.status,created_at:a.created_at,evidence_count:8+i*3,validation_outcome:null}));
const action={action:'block_ip_simulated',target:'198.51.100.42',risk:'低风险',impact:'仅限验收样例',preview:'模拟限制异常来源',rollback:'撤销模拟限制',verification_query:{filters:{source_ip:'198.51.100.42'}}};
const plans=[{
  response_plan_id:'RP-P2-001',incident_id:'IN-P2-001',investigation_id:'IV-P2-001',alert_id:alerts[0].alert_id,alert_title:alerts[0].title,severity:'high',incident_status:'awaiting_approval',
  summary:'限制异常来源并验证正常访问',actions:[action],created_at:alerts[0].created_at,requires_approval:true,evidence_ids:['EV-P2-001'],decision_state:'pending',is_current:true,execution_mode:'simulation',
  risk_level:'low',risk_reason:'仅限隔离样例',affected_assets:['198.51.100.42'],business_impact:'不影响生产链路',expires_at:'2026-11-05T05:30:00.000Z',is_expired:false,
  rollback_steps:[{step_id:'RB-P2-001',description:'撤销模拟限制',target:'198.51.100.42',expected_result:'恢复样例访问',evidence_ids:['EV-P2-001']}],
  validation_checks:[{check_id:'VC-P2-001',description:'复查正常访问',target:'198.51.100.42',expected_result:'正常访问不受影响',query:{filters:{source_ip:'198.51.100.42'}},evidence_ids:['EV-P2-001']}],plan_version:'a'.repeat(64),
}];
function page(items,url) {return {items,total:items.length,page:Number(url.searchParams.get('page')||1),page_size:Number(url.searchParams.get('page_size')||20)};}
module.exports={alerts,health,summary,incidents,plans,page};
