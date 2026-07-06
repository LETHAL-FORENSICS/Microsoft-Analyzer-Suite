-- Title: ParticipatingDomains / ParticipatingTenantIds (Stats)
-- Description: Creates a statistical breakdown of ParticipatingDomains / ParticipatingTenantIds properties
-- Id: 0e8e5057-3e41-4637-a8d8-bf3fdb49b5a2
-- Author: Martin Willing
-- Date: 2026-06-21
WITH ResultSet AS (
SELECT 
  NULLIF(array_to_string(CAST(auditData->'ParticipantInfo'->'ParticipatingDomains' AS VARCHAR[]), ', '), '') AS ParticipatingDomains,
  NULLIF(array_to_string(CAST(auditData->'ParticipantInfo'->'ParticipatingTenantIds' AS VARCHAR[]), ', '), '') AS ParticipatingTenantIds,
  json_extract_string(auditData, '$.ParticipantInfo.HasForeignTenantUsers') AS HasForeignTenantUsers,
FROM 'UAL'
WHERE auditLogRecordType == 'MicrosoftTeams' AND ParticipatingDomains != 'NULL'
)
SELECT
  ParticipatingDomains,
  ParticipatingTenantIds,
  HasForeignTenantUsers,
  COUNT(ParticipatingDomains) AS Count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'ResultSet'
GROUP BY ALL 
ORDER BY Count DESC;