-- Title: MessageCreatedHasLink
-- Description: A user sends a message containing a URL link in Teams
-- Id: 2a6f9610-ba46-4767-afd2-3ed0ccd991fc
-- Author: Martin Willing
-- Date: 2026-07-05
WITH ResultSet AS (
SELECT 
  CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  organizationId AS OrganizationId,
  userId AS UserId,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  json_extract_string(auditData, '$.Workload') AS Workload,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.ClientIP') AS IPAddress,
  json_extract_string(auditData, '$.ChatThreadId') AS ChatThreadId,
  json_extract_string(auditData, '$.CommunicationType') AS CommunicationType,
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  CAST(json_extract(auditData, '$.IsBilateral') AS BOOLEAN) AS IsBilateral,
  json_extract_string(auditData, '$.MessageId') AS MessageId,
  json_extract_string(auditData, '$.MessageVersion') AS MessageVersion,
  json_extract_string(auditData, '$.ResourceTenantId') AS ResourceTenantId,
  json_extract_string(auditData, '$.ItemName') AS ItemName,
  array_to_string(json_transform(json_extract(auditData, '$.MessageURLs'), '["VARCHAR"]'), ', ') AS MessageURLs,
  json_extract_string(auditData, '$.AppAccessContext.AADSessionId') AS SessionId,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  -- ExtraProperties
  list_extract(list_filter(json_transform(json_extract(auditData, '$.ExtraProperties'), '["STRUCT(Key VARCHAR, Value VARCHAR)"]'), lambda x: x.Key = 'TimeZone'), 1).Value AS TimeZone,
  list_extract(list_filter(json_transform(json_extract(auditData, '$.ExtraProperties'), '["STRUCT(Key VARCHAR, Value VARCHAR)"]'), lambda x: x.Key = 'ClientUtcOffsetSeconds'), 1).Value AS ClientUtcOffsetSeconds,
  list_extract(list_filter(json_transform(json_extract(auditData, '$.ExtraProperties'), '["STRUCT(Key VARCHAR, Value VARCHAR)"]'), lambda x: x.Key = 'OsName'), 1).Value AS OsName,
  list_extract(list_filter(json_transform(json_extract(auditData, '$.ExtraProperties'), '["STRUCT(Key VARCHAR, Value VARCHAR)"]'), lambda x: x.Key = 'OsVersion'), 1).Value AS OsVersion,
  list_extract(list_filter(json_transform(json_extract(auditData, '$.ExtraProperties'), '["STRUCT(Key VARCHAR, Value VARCHAR)"]'), lambda x: x.Key = 'Country'), 1).Value AS Language,
  list_extract(list_filter(json_transform(json_extract(auditData, '$.ExtraProperties'), '["STRUCT(Key VARCHAR, Value VARCHAR)"]'), lambda x: x.Key = 'ClientName'), 1).Value AS ClientName,
  list_extract(list_filter(json_transform(json_extract(auditData, '$.ExtraProperties'), '["STRUCT(Key VARCHAR, Value VARCHAR)"]'), lambda x: x.Key = 'ClientVersion'), 1).Value AS ClientVersion,
  -- MessageLinks
  array_to_string(list_transform(json_transform(json_extract(auditData, '$.MessageLinks'), '["STRUCT(Url VARCHAR)"]'), lambda x: x.Url), ', ') AS MessageLinks,
  -- ParticipantInfo
  json_extract_string(auditData, '$.ParticipantInfo.HasForeignTenantUsers') AS HasForeignTenantUsers,
  json_extract_string(auditData, '$.ParticipantInfo.HasGuestUsers') AS HasGuestUsers,
  json_extract_string(auditData, '$.ParticipantInfo.HasOtherGuestUsers') AS HasOtherGuestUsers,
  json_extract_string(auditData, '$.ParticipantInfo.HasUnauthenticatedUsers') AS HasUnauthenticatedUsers,
  NULLIF(array_to_string(json_transform(json_extract(auditData, '$.ParticipantInfo.ParticipatingTenantIds'), '["VARCHAR"]'), ', '), '') AS ParticipatingTenantIds, 
  NULLIF(array_to_string(json_transform(json_extract(auditData, '$.ParticipantInfo.ParticipatingDomains'), '["VARCHAR"]'), ', '), '') AS ParticipatingDomains,
  CASE 
  WHEN json_extract(auditData, '$.ParticipantInfo.ParticipatingSIPDomains') IS NULL 
    OR json_array_length(json_extract(auditData, '$.ParticipantInfo.ParticipatingSIPDomains')) = 0 
  THEN NULL
  ELSE array_to_string(
      list_filter(
        list_transform(
          json_transform(json_extract(auditData, '$.ParticipantInfo.ParticipatingSIPDomains'), '["STRUCT(DomainName VARCHAR, TenantId VARCHAR)"]'),
          lambda x: CASE WHEN NULLIF(x.DomainName, '') IS NULL OR NULLIF(x.TenantId, '') IS NULL THEN NULL 
                         ELSE x.DomainName || ' (' || x.TenantId || ')' END
        ),
        lambda x: x IS NOT NULL -- Fixed: Converted to 'lambda x: expression' format
      ), 
      ', '
    )
  END AS ParticipatingSIPDomains,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'MessageCreatedHasLink'
)
SELECT
  CreationTime,
  OrganizationId,
  UserId,
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
  DeviceId,
  IsBilateral,
  MessageId,
  MessageVersion,
  ResourceTenantId,
  ItemName,
  MessageURLs,
  SessionId,
  IssuedAtTime,
  UniqueTokenId,
  TimeZone,
  ClientUtcOffsetSeconds,
  OsName,
  OsVersion,
  Language,
  ClientName,
  ClientVersion,
  MessageLinks,
  HasForeignTenantUsers,
  HasGuestUsers,
  HasOtherGuestUsers,
  HasUnauthenticatedUsers,
  ParticipatingTenantIds,
  ParticipatingDomains,
  ParticipatingSIPDomains,
  Id
FROM ResultSet
LEFT JOIN IPinfo_Lite
  ON TRY_CAST(IPAddress AS INET) <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;