-- Title: Email Forwarding via New-InboxRule / Set-InboxRule
-- Description: Detects Email Forwarding via New-InboxRule and Set-InboxRule
-- Id: 56a5e744-07c1-469c-b405-d2d424899eb3
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
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Name'), 1).Value AS FriendlyName,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Identity'), 1).Value AS Identity,
  COALESCE(
    FriendlyName,
    Identity
  ) AS Name,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'From'), 1).Value AS "From",
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'MarkAsRead'), 1).Value AS MarkAsRead,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'DeleteMessage'), 1).Value AS DeleteMessage,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'MoveToFolder'), 1).Value AS MoveToFolder,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'Force'), 1).Value AS Force,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'AlwaysDeleteOutlookRulesBlob'), 1).Value AS AlwaysDeleteOutlookRulesBlob,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'StopProcessingRules'), 1).Value AS StopProcessingRules,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'FromAddressContainsWords'), 1).Value AS FromAddressContainsWords,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'SubjectContainsWords'), 1).Value AS SubjectContainsWords,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'BodyContainsWords'), 1).Value AS BodyContainsWords,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'MyNameInToOrCcBox'), 1).Value AS MyNameInToOrCcBox,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'ForwardAsAttachmentTo'), 1).Value AS ForwardAsAttachmentTo,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'ForwardTo'), 1).Value AS ForwardTo,
  list_extract(list_filter(auditData.Parameters, lambda x: x.Name = 'RedirectTo'), 1).Value AS RedirectTo,
  -- Email Forwarding
  COALESCE(
    ForwardAsAttachmentTo,
    ForwardTo,
    RedirectTo
  ) AS EmailForwarding,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'   
LEFT JOIN MicrosoftApps ON (json_extract_string(auditData, '$.AppId')) = MicrosoftApps.AppId
WHERE 
  (Operation = 'New-InboxRule' OR Operation = 'Set-InboxRule' OR Operation = 'set-InboxRule')
  AND EmailForwarding IS NOT NULL
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
  Name,
  "From",
  MarkAsRead,
  DeleteMessage,
  MoveToFolder,
  Force,
  AlwaysDeleteOutlookRulesBlob,
  StopProcessingRules,
  FromAddressContainsWords,
  SubjectContainsWords,
  BodyContainsWords,
  MyNameInToOrCcBox,
  ForwardAsAttachmentTo,
  ForwardTo,
  RedirectTo,
  IssuedAtTime,
  UniqueTokenId,
  DeviceId,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr;