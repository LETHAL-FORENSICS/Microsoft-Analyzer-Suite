-- Title: MessageSent
-- Description: A new message was posted to a chat or a channel
-- Id: ef212ccc-51bd-4948-8f6b-6e66f21a27bb
-- Author: Martin Willing
-- Date: 2026-07-04
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
  json_extract_string(auditData, '$.AADGroupId') AS AADGroupId,
  json_extract_string(auditData, '$.ChannelGuid') AS ChannelGuid,
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  json_extract_string(auditData, '$.MessageId') AS MessageId,
  json_extract_string(auditData, '$.MessageVersion') AS MessageVersion,
  json_extract_string(auditData, '$.ParentMessageId') AS ParentMessageId,
  json_extract_string(auditData, '$.ResourceTenantId') AS ResourceTenantId,
  json_extract_string(auditData, '$.TeamGuid') AS TeamGuid,
  json_extract_string(auditData, '$.ChannelName') AS ChannelName,
  json_extract_string(auditData, '$.ItemName') AS ItemName,
  json_extract_string(auditData, '$.TeamName') AS TeamName,
  -- ExtraProperties
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'TimeZone'), 1).Value AS TimeZone,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'ClientUtcOffsetSeconds'), 1).Value AS ClientUtcOffsetSeconds,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'OsName'), 1).Value AS OsName,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'OsVersion'), 1).Value AS OsVersion,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'Country'), 1).Value AS Language,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'ClientName'), 1).Value AS ClientName,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'ClientVersion'), 1).Value AS ClientVersion,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'MessageSent'
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
  AADGroupId,
  ChannelGuid,
  DeviceId,
  MessageId,
  MessageVersion,
  ParentMessageId,
  ResourceTenantId,
  TeamGuid,
  ChannelName,
  ItemName,
  TeamName,
  TimeZone,
  ClientUtcOffsetSeconds,
  OsName,
  OsVersion,
  Language,
  ClientName,
  ClientVersion,
  Id
FROM ResultSet
LEFT JOIN IPinfo_Lite
  ON TRY_CAST(IPAddress AS INET) <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;