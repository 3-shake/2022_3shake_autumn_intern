// POST受信時
function doPost(event) {
  // contentをJSONにパースする
  const params = JSON.parse(event.postData.getDataAsString());
  
  try {
    registerReoprt(params);
  } catch (err) {
    // エラー時はlogsシートにログを残す
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheat = ss.getSheetByName('logs')　|| ss.insertSheet().setName('logs');
    sheat.appendRow([err]);
  }
  
  const output = ContentService.createTextOutput().setContent("success");
  return output;
}

function registerReoprt(report) {
  // このPoCではVulnerabilityReportのみ対応
  if (report?.kind !== 'VulnerabilityReport') return;

  // napespaceとリソース名からシート名を定義
  const namespace = report.metadata.labels["trivy-operator.resource.namespace"];
  const resourceName = report.metadata.labels["trivy-operator.resource.name"];
  const sheetName = namespace + '/' + resourceName;

  // シート取得
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(sheetName) || ss.insertSheet().setName(sheetName);

  // 既知の脆弱性の対応状況マップstateMapを取得
  // Map<resource/vulnerabilityID/severity/installedVersion, status>
  const stateMap = getStateMap(sheet);

  // レポートの脆弱性情報とstateMapから書き込み用データを生成
  const data = createData(report.report.vulnerabilities, stateMap);
  
  // シートへのデータ書き込み
  setData(sheet, data)
}

function getStateMap(sheet) {
  const rangeValues = sheet?.getDataRange().getValues().slice(1);
  const stateMap = new Map(rangeValues?.map(row => [row.slice(0, 4).join(';'), 10]));
  return stateMap;
}

function createData(vulnerabilities, stateMap) {
  const keys = ['resource', 'vulnerabilityID', 'severity', 'installedVersion', 'fixedVersion', 'title', 'score', 'primaryLink', 'links', 'target'];
  const svr = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4, 'NONE': 5 };
  const comp = (a, b) => [a[0] > b[0], svr[a[2]] > svr[b[2]], a[1] > b[1]].reduce((x, y) => x << 1 | y);
  const data = vulnerabilities
    .map(item => keys.map(k => (typeof item[k] == 'object') ? JSON.stringify(item[k]) : item[k]))
    .sort((a, b) => comp(a, b) - comp(b, a))
    .map(row => [...row, stateMap.get(row.slice(0, 4).join(';')) || 'unchecked']);
  return data;
}

function setData(sheet, data) {
  const maxCols = sheet.getMaxColumns();
  const maxRows = sheet.getMaxRows();
  if (maxCols > 1) sheet.deleteColumns(1, maxCols - 1);
  if (maxRows > 1) sheet.deleteRows(1, maxRows - 1);

  const keys = ['resource', 'vulnerabilityID', 'severity', 'installedVersion', 'fixedVersion', 'title', 'score', 'primaryLink', 'links', 'target', 'state'];
  data.unshift(keys);
  const range = sheet.getRange(1, 1, data.length, keys.length);
  range.setValues(data);
  range.createFilter();

  if (data.length > 0) sheet.setFrozenRows(1);
  return sheet;
}
