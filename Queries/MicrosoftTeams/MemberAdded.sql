-- Title: MemberAdded
-- Description: A team owner adds members to a team, channel, or group chat.
-- Id: 1461c35a-6a65-42d0-92c2-f260d4e4d665
-- Author: Martin Willing
-- Date: 2026-07-05
WITH ResultSet AS (
SELECT 
  CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  userId AS UserId,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  json_extract_string(auditData, '$.Workload') AS Workload,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.ChatThreadId') AS ChatThreadId,
  json_extract_string(auditData, '$.CommunicationType') AS CommunicationType,
  json_extract_string(auditData, '$.ResourceTenantId') AS ResourceTenantId,
  json_extract_string(auditData, '$.UserTenantId') AS UserTenantId,
  -- Members
  json_extract_string(auditData, '$.Members[0].OrganizationId') AS OrganizationId,
  json_extract_string(auditData, '$.Members[0].DisplayName') AS DisplayName,
  CASE json_extract_string(auditData, '$.Members[0].Role')
    WHEN '1' THEN 'Member'
    WHEN '2' THEN 'Owner'
    WHEN '3' THEN 'Guest'
    ELSE 'Unknown'
  END AS Role,
  json_extract_string(auditData, '$.Members[0].UPN') AS UPN,
  -- ParticipantInfo
  json_extract_string(auditData, '$.ParticipantInfo.HasForeignTenantUsers') AS HasForeignTenantUsers,
  json_extract_string(auditData, '$.ParticipantInfo.HasGuestUsers') AS HasGuestUsers,
  json_extract_string(auditData, '$.ParticipantInfo.HasOtherGuestUsers') AS HasOtherGuestUsers,
  json_extract_string(auditData, '$.ParticipantInfo.HasUnauthenticatedUsers') AS HasUnauthenticatedUsers,
  NULLIF(array_to_string(CAST(auditData->'ParticipantInfo'->'ParticipatingDomains' AS VARCHAR[]), ', '), '') AS ParticipatingDomains,
  NULLIF(array_to_string(CAST(auditData->'ParticipantInfo'->'ParticipatingTenantIds' AS VARCHAR[]), ', '), '') AS ParticipatingTenantIds, 
  array_to_string(
    list_transform(
      json_transform(auditData->'ParticipantInfo'->'ParticipatingSIPDomains', '["STRUCT(DomainName VARCHAR, TenantId VARCHAR)"]'),
      lambda x: x.DomainName || ' (' || x.TenantId || ')'
    ), 
    ', '
  ) AS ParticipatingSIPDomains,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'MemberAdded'
)
SELECT
  CreationTime,
  UserId,
  UserPrincipalName,
  UserType,
  Workload,
  RecordType,
  Operation,
  ChatThreadId,
  CommunicationType,
  ResourceTenantId,
  UserTenantId,
  OrganizationId,
  DisplayName,
  Role,
  UPN,
  HasForeignTenantUsers,
  HasGuestUsers,
  HasOtherGuestUsers,
  HasUnauthenticatedUsers,
  ParticipatingDomains,
  ParticipatingTenantIds,
  ParticipatingSIPDomains,
  Id
FROM 'ResultSet'
ORDER BY CreationTime DESC;