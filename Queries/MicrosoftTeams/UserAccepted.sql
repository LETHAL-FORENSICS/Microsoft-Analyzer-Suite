-- Title: UserAccepted
-- Description: Accept a new message from a person who never established contact with.
-- Id: 09a5be59-abc8-4eab-b8b0-5f39623ce4a6
-- Author: Martin Willing
-- Date: 2026-07-05
WITH ResultSet AS (
SELECT 
  CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  userId AS UserId,
  organizationId AS OrganizationId,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  json_extract_string(auditData, '$.Workload') AS Workload,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.AppAccessContext.AADSessionId') AS SessionId,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  -- Members
  json_extract_string(auditData, '$.Members[0].MRI') AS MessagingResourceIdentifier,
  json_extract_string(auditData, '$.Members[0].OrganizationId') AS ForeignTenantId,
  json_extract_string(auditData, '$.Members[0].UserObjectId') AS UserObjectId,
  CASE json_extract_string(auditData, '$.Members[0].Role')
    WHEN '1' THEN 'Member'
    WHEN '2' THEN 'Owner'
    WHEN '3' THEN 'Guest'
    ELSE 'Unknown'
  END AS Role,
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'UserAccepted'
)
SELECT
  CreationTime,
  UserId,
  OrganizationId,
  UserPrincipalName,
  UserType,
  Workload,
  RecordType,
  Operation,
  SessionId,
  IssuedAtTime,
  UniqueTokenId,
  MessagingResourceIdentifier,
  ForeignTenantId,
  UserObjectId,
  Role,
  DeviceId,
  Id
FROM 'ResultSet'
ORDER BY CreationTime DESC;