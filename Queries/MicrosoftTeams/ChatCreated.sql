-- Title: ChatCreated
-- Description: A Teams chat was created.
-- Id: 67641c32-2b77-4315-a1cf-ddbb93afd28b
-- Author: Martin Willing
-- Date: 2026-06-21
INSTALL inet;
LOAD inet;
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
  json_extract_string(auditData, '$.ClientIP') AS IPAddress,
  json_extract_string(auditData, '$.ChatThreadId') AS ChatThreadId,
  json_extract_string(auditData, '$.CommunicationType') AS CommunicationType,
  json_extract_string(auditData, '$.IsBilateral') AS IsBilateral,
  array_to_string(json_transform(auditData->'Members', '["STRUCT(OrganizationId VARCHAR, DisplayName VARCHAR, UPN VARCHAR)"]'), ', ') AS Members,
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
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'ChatCreated'
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
  IPAddress,
  IPinfo_Lite.country_code AS CountryCode,
  IPinfo_Lite.country AS CountryName,
  IPinfo_Lite.asn AS ASN,
  IPinfo_Lite.as_name AS OrgName,
  ChatThreadId,
  CommunicationType,
  IsBilateral,
  Members,
  HasForeignTenantUsers,
  HasGuestUsers,
  HasOtherGuestUsers,
  HasUnauthenticatedUsers,
  ParticipatingDomains,
  ParticipatingTenantIds,
  ParticipatingSIPDomains,
  DeviceId,
  Id
FROM ResultSet
LEFT JOIN IPinfo_Lite
  ON TRY_CAST(IPAddress AS INET) <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;