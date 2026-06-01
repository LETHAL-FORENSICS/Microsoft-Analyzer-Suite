-- Title: Set-MailboxJunkEmailConfiguration
-- Description: Used by adversaries to manipulate the junk email settings of mailboxes (e.g. to disable spam filtering for specific senders, allowing phishing and malicious emails to bypass Microsoft Defender and Exchange Online)
-- Id: 209370a6-a90e-49b6-abb9-a6dbcb06ab70
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
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'BlockedSendersAndDomains'), 1).Value AS BlockedSendersAndDomains,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'TrustedSendersAndDomains'), 1).Value AS TrustedSendersAndDomains,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Enabled'), 1).Value AS Enabled,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'TrustedListsOnly'), 1).Value AS TrustedListsOnly,
  json_extract_string(auditData, '$.OrganizationName') AS OrganizationName,
  json_extract_string(auditData, '$.OriginatingServer') AS OriginatingServer,
  json_extract_string(auditData, '$.RequestId') AS RequestId,
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
WHERE Operation = 'Set-MailboxJunkEmailConfiguration'
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
  BlockedSendersAndDomains,
  TrustedSendersAndDomains,
  Enabled,
  TrustedListsOnly,
  OrganizationName,
  OriginatingServer,
  RequestId,
  SessionId,
  IssuedAtTime,
  UniqueTokenId,
  DeviceId,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;