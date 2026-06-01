-- Title: Enable-InboxRule
-- Description: Enable an existing Inbox Rule in a mailbox (Suspicious Operation)
-- Id: 12b3e039-8260-4832-8b7d-1e184c3897e1
-- Author: Martin Willing
-- Date: 2026-05-17
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
  objectId AS ObjectId,
  json_extract_string(auditData, '$.AppId') AS AppId,
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
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Confirm'), 1).Value AS Confirm,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Identity'), 1).Value AS Identity,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Mailbox'), 1).Value AS Mailbox,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'   
LEFT JOIN MicrosoftApps ON (json_extract_string(auditData, '$.AppId')) = MicrosoftApps.AppId
WHERE Operation = 'Enable-InboxRule'
ORDER BY CreationTime DESC
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
  Mailbox,
  Identity,
  Confirm,
  IssuedAtTime,
  UniqueTokenId,
  DeviceId,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr;