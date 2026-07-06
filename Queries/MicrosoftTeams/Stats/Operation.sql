-- Title: Operation (Stats)
-- Description: Creates a statistical breakdown of Operation property
-- Id: 351a14b6-4a27-4767-ad92-493dd40fcb2b
-- Author: Martin Willing
-- Date: 2026-06-21
SELECT
  operation AS Operation,
  COUNT(Operation) AS Count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'UAL'
WHERE auditLogRecordType == 'MicrosoftTeams' AND Operation != 'NULL'
GROUP BY Operation
ORDER BY Count DESC;