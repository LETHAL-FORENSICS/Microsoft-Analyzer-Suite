-- Title: CommunicationType (Stats)
-- Description: Creates a statistical breakdown of CommunicationType property
-- Id: 9c989003-ed33-449a-8f3c-12a2b13a5d30
-- Author: Martin Willing
-- Date: 2026-06-21
SELECT
  json_extract_string(auditData, '$.CommunicationType') AS CommunicationType,
  COUNT(json_extract_string(auditData, '$.CommunicationType')) AS Count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'UAL'
WHERE auditLogRecordType == 'MicrosoftTeams' AND CommunicationType != 'NULL'
GROUP BY CommunicationType
ORDER BY Count DESC;