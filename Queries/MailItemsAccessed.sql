-- Title: MailItemsAccessed View
-- Description: Creates a view and breakdown of MailItemsAccessed events to trace email access
-- Id: 837c47a6-d886-4e32-94a4-d8b1cdae8345
-- Author: Martin Willing
-- Date: 2026-05-30
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
  json_extract_string(auditData, '$.ResultStatus') AS ResultStatus,
  NULLIF(trim(auditData->>'$.AppId'), '') AS AppId,
  CASE 
    WHEN NULLIF(trim(auditData->>'$.AppId'), '') IS NULL THEN NULL
    WHEN "Application-Blacklist".AppId IS NOT NULL THEN "Application-Blacklist".AppDisplayName
    WHEN MicrosoftApps.AppDisplayName IS NULL THEN 'Third Party Application'
    ELSE MicrosoftApps.AppDisplayName 
  END AS AppDisplayName,
  COALESCE(
    json_extract_string(auditData, '$.ClientIP'),
    json_extract_string(auditData, '$.ClientIPAddress'),
    json_extract_string(auditData, '$.ActorIpAddress'),
  ) AS Merged, 
  CASE 
    -- When IPv6 with square brackets and port number --> Remove square brackets and port number
    WHEN Merged LIKE '[%]:%' THEN regexp_extract(Merged, '\[(.*)\]', 1)
    -- When IPv4 with port number --> Remove port number
    WHEN Merged LIKE '%.%.%.%:%' THEN regexp_replace(Merged, ':\d+$', '')
    -- When IPv4-mapped IPv6 address --> Remove prefix "^::ffff:"
    WHEN Merged LIKE '::ffff:%' THEN regexp_extract(Merged, '^::ffff:(.+)$', 1)
    ELSE Merged
  END AS IPAddress,
  json_extract_string(auditData, '$.ClientInfoString') AS ClientInfoString,
  json_extract_string(auditData, '$.ActorInfoString') AS ActorInfoString,
  json_extract_string(auditData, '$.ExternalAccess') AS ExternalAccess,
  json_extract_string(auditData, '$.InternalLogonType') AS InternalLogonType,
  json_extract_string(auditData, '$.LogonType') AS LogonType,
  json_extract_string(auditData, '$.LogonUserSid') AS LogonUserSid,
  json_extract_string(auditData, '$.MailboxGuid') AS MailboxGuid,
  json_extract_string(auditData, '$.MailboxOwnerSid') AS MailboxOwnerSid,
  json_extract_string(auditData, '$.MailboxOwnerUPN') AS MailboxOwnerUPN,
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'MailAccessType'), 1).Value AS MailAccessType,
  COALESCE(list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'IsThrottled'), 1).Value, 'false') AS IsThrottled,
  json_extract_string(auditData, '$.OrganizationId') AS OrganizationId,
  json_extract_string(auditData, '$.OrganizationName') AS OrganizationName,
  regexp_replace(json_extract_string(auditData, '$.OriginatingServer'), '\r\n$', '') AS OriginatingServer,
  ( SELECT string_agg(ClientRequestId_Values, chr(10)) 
    FROM (SELECT unnest(json_extract_string(auditData, '$.Folders[*].FolderItems[*].ClientRequestId')) AS ClientRequestId_Values)
  ) AS ClientRequestId,
  ( SELECT string_agg(InternetMessageId_Values, chr(10)) 
    FROM (SELECT unnest(json_extract_string(auditData, '$.Folders[*].FolderItems[*].InternetMessageId')) AS InternetMessageId_Values)
  ) AS InternetMessageId,
  ( SELECT string_agg(SizeInBytes_Values, chr(10)) 
    FROM (SELECT unnest(json_extract_string(auditData, '$.Folders[*].FolderItems[*].SizeInBytes')) AS SizeInBytes_Values)
  ) AS SizeInBytes,
  list_aggregate(list_transform(json_transform(auditData -> 'Folders', '["JSON"]'), lambda x: x ->> 'Id'), 'string_agg', chr(10)) AS FolderId,
  list_aggregate(list_transform(json_transform(auditData -> 'Folders', '["JSON"]'), lambda x: x ->> 'Path'), 'string_agg', chr(10)) AS Folder,
  COALESCE(
    json_extract_string(auditData, '$.SessionId'),
    json_extract_string(auditData, '$.AppAccessContext.AADSessionId'),
    list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'SessionId'), 1).Value,
  ) AS SessionId,
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  json_extract_string(auditData, '$.OperationCount') AS OperationCount, -- Aggregated Events
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
LEFT JOIN MicrosoftApps 
  ON json_extract_string(auditData, '$.AppId') = MicrosoftApps.AppId -- First-Party Applications
LEFT JOIN "Application-Blacklist"
  ON json_extract_string(auditData, '$.AppId') = "Application-Blacklist".AppId -- Blacklisted Applications
WHERE Operation = 'MailItemsAccessed'
)
SELECT
  CreationTime,
  UserPrincipalName,
  UserType,
  Workload,
  RecordType,
  Operation,
  ResultStatus,
  AppId,
  AppDisplayName,
  IPAddress,
  IPinfo_Lite.country_code AS CountryCode,
  IPinfo_Lite.country AS CountryName,
  IPinfo_Lite.asn AS ASN,
  IPinfo_Lite.as_name AS OrgName,
  ClientInfoString,
  ActorInfoString,
  ExternalAccess,
  InternalLogonType,
  LogonType,
  LogonUserSid,
  MailboxGuid,
  MailboxOwnerSid,
  MailboxOwnerUPN,
  MailAccessType,
  IsThrottled,
  OrganizationId,
  OrganizationName,
  OriginatingServer,
  ClientRequestId,
  InternetMessageId,
  SizeInBytes,
  FolderId,
  Folder,
  DeviceId,
  SessionId,
  OperationCount,
  IssuedAtTime,
  UniqueTokenId,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;