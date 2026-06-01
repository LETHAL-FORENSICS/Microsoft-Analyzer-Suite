-- Title: Email Forwarding via New-TransportRule / Set-TransportRule
-- Description: Detects Email Forwarding via New-TransportRule and Set-TransportRule
-- Id: 34ea4472-f3da-42d7-9209-e5a31f6eaf6d
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
    json_extract_string(auditData, '$.ActorIpAddress')
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
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Name'), 1).Value AS Name,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Identity'), 1).Value AS Identity,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'BlindCopyTo'), 1).Value AS BlindCopyTo,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'CopyTo'), 1).Value AS CopyTo,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'RedirectMessageTo'), 1).Value AS RedirectMessageTo,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Enabled'), 1).Value AS Enabled,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'StopRuleProcessing'), 1).Value AS StopRuleProcessing,
  NULLIF(list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Comments'), 1).Value, '') AS Comments,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Priority'), 1).Value AS Priority,
  NULLIF(list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'FromScope'), 1).Value, '') AS FromScope,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'SenderDomainIs'), 1).Value AS SenderDomainIs,
  try_strptime(
    list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'ActivationDate'), 1).Value, 
    '%-m/%d/%Y %-I:%M:%S %p'
) AS ActivationDate,
try_strptime(
    list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'ExpiryDate'), 1).Value, 
    '%-m/%d/%Y %-I:%M:%S %p'
) AS ExpiryDate,
  -- Email Forwarding
  COALESCE(
    BlindCopyTo,
    CopyTo,
    RedirectMessageTo
  ) AS EmailForwarding,
  COALESCE(
  json_extract_string(auditData, '$.SessionId'),
  json_extract_string(auditData, '$.AppAccessContext.AADSessionId'),
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'SessionId'), 1).Value,
) AS SessionId,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'   
LEFT JOIN MicrosoftApps ON (json_extract_string(auditData, '$.AppId')) = MicrosoftApps.AppId
WHERE 
  (Operation = 'New-TransportRule' OR Operation = 'Set-TransportRule')
  AND EmailForwarding IS NOT NULL
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
  Name,
  Identity,
  Comments,
  Priority,
  FromScope,
  SenderDomainIs,
  ActivationDate,
  ExpiryDate,
  BlindCopyTo,
  CopyTo,
  RedirectMessageTo,
  StopRuleProcessing,
  Enabled,
  SessionId,
  IssuedAtTime,
  UniqueTokenId,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;