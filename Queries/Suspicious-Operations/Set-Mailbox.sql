-- Title: Set-Mailbox
-- Description: Modifies the settings and attributes of an existing mailbox in Microsoft Exchange Server and Exchange Online.
-- Id: 265073fd-5096-4e50-a7b7-d91728f7d508
-- Author: Martin Willing
-- Date: 2026-05-25
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
  NULLIF(trim(auditData->>'$.objectId'), '') AS ObjectId,
  COALESCE(
    NULLIF(json_extract_string(auditData, '$.AppId'), ''),
    NULLIF(json_extract_string(auditData, '$.ClientAppId'), ''),
  ) AS AppId,
  MicrosoftApps.AppDisplayName AS AppDisplayName,
  json_extract_string(auditData, '$.AppPoolName') AS AppPoolName,
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
  -- Parameters
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Identity'), 1).Value AS Identity,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'ForwardingAddress'), 1).Value AS ForwardingAddress,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'ForwardingSmtpAddress'), 1).Value AS ForwardingSmtpAddress,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'DeliverToMailboxAndForward'), 1).Value AS DeliverToMailboxAndForward,
  COALESCE(
  json_extract_string(auditData, '$.SessionId'),
  json_extract_string(auditData, '$.AppAccessContext.AADSessionId'),
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'SessionId'), 1).Value,
  ) AS SessionId,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
LEFT JOIN MicrosoftApps ON (json_extract_string(auditData, '$.AppId')) = MicrosoftApps.AppId
WHERE Operation = 'Set-Mailbox'
)
SELECT
  CreationTime,
  UserPrincipalName,
  UserType,
  Workload,
  RecordType,
  Operation,
  ResultStatus,
  ObjectId,
  AppId,
  AppDisplayName,
  AppPoolName,
  IPAddress,
  IPinfo_Lite.country_code AS CountryCode,
  IPinfo_Lite.country AS CountryName,
  IPinfo_Lite.asn AS ASN,
  IPinfo_Lite.as_name AS OrgName,
  Identity,
  ForwardingAddress,
  ForwardingSmtpAddress,
  DeliverToMailboxAndForward,
  SessionId,
  IssuedAtTime,
  UniqueTokenId,
  DeviceId,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;