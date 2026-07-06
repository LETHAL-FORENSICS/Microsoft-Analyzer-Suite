-- Title: MicrosoftTeams View
-- Description: Creates a view and breakdown of MicrosoftTeams events
-- Id: 65a9a914-788f-451c-8b01-111a7f27b0be
-- Author: Martin Willing
-- Date: 2026-06-20
INSTALL inet;
LOAD inet;
WITH ResultSet AS (
SELECT 
  CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  json_extract_string(auditData, '$.Workload') AS Workload,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Workload = 'MicrosoftTeams'
)
SELECT
  CreationTime,
  UserPrincipalName,
  UserType,
  Workload,
  RecordType,
  Operation,
  Id
FROM 'ResultSet'
ORDER BY CreationTime DESC;