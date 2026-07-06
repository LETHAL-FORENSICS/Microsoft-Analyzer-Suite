-- Title: TeamsImpersonationDetected
-- Description: An external message sender is detected to have potential impersonation activity.
-- Id: 768dd3b3-2479-48ba-974a-9c75a4fba6ac
-- Author: Martin Willing
-- Date: 2026-06-20
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
  json_extract_string(auditData, '$.ChatThreadId') AS ChatThreadId,
  json_extract_string(auditData, '$.ImpersonationType') AS ImpersonationType,
  json_extract_string(auditData, '$.Sender.MRI') AS MessagingResourceIdentifier,
  json_extract_string(auditData, '$.Sender.OrganizationId') AS ForeignTenantId,
  json_extract_string(auditData, '$.Sender.UserObjectId') AS UserObjectId,
  json_extract_string(auditData, '$.Sender.DisplayName') AS DisplayName,
  json_extract_string(auditData, '$.Sender.UPN') AS UPN,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'TeamsImpersonationDetected'
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
  ChatThreadId,
  ImpersonationType,
  MessagingResourceIdentifier,
  ForeignTenantId,
  UserObjectId,
  DisplayName,
  UPN,
  Id
FROM 'ResultSet'
ORDER BY CreationTime DESC;