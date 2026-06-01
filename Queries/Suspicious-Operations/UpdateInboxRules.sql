-- Title: UpdateInboxRules
-- Description: UpdateInboxRules is used to create an Inbox rule, to modify an Inbox rule, or to delete an Inbox rule using Exchange Web Services (EWS)
-- Id: 9e2f3b5e-b089-4590-b062-7330cf12c510
-- Author: Martin Willing
-- Date: 2026-05-19
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
  json_extract_string(auditData, '$.MailboxOwnerUPN') AS MailboxOwnerUPN,
  json_extract_string(auditData, '$.MailboxGuid') AS MailboxGuid,
  -- OperationProperties
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'Actions'), 1).Value AS Actions,
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'Conditions'), 1).Value AS Conditions,
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'Provider'), 1).Value AS Provider,
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'RemoveOutlookRuleBlob'), 1).Value AS RemoveOutlookRuleBlob,
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'Name'), 1).Value AS Name,
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'IsNew'), 1).Value AS IsNew,
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'IsDirty'), 1).Value AS IsDirty, --  It becomes true when a property has been modified in local memory but has not yet been saved (committed) to the server.
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'RuleOperation'), 1).Value AS RuleOperation,
  list_extract(list_filter(auditData.OperationProperties, lambda x: x.Name = 'ServerRule'), 1).Value AS ServerRule,
  COALESCE(
    json_extract_string(auditData, '$.SessionId'),
    json_extract_string(auditData, '$.AppAccessContext.AADSessionId'),
    list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'SessionId'), 1).Value,
  ) AS SessionId,
  json_extract_string(auditData, '$.InterSystemsId') AS InterSystemsId,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  json_extract_string(auditData, '$.AuthType') AS AuthType,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
LEFT JOIN MicrosoftApps 
  ON json_extract_string(auditData, '$.AppId') = MicrosoftApps.AppId -- First-Party Applications
LEFT JOIN "Application-Blacklist"
  ON json_extract_string(auditData, '$.AppId') = "Application-Blacklist".AppId -- Blacklisted Applications
WHERE Operation = 'UpdateInboxRules'
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
  MailboxOwnerUPN,
  MailboxGuid,
  Actions,
  Conditions,
  Provider,
  RemoveOutlookRuleBlob,
  Name,
  IsNew,
  IsDirty,
  RuleOperation,
  ServerRule,
  SessionId,
  IssuedAtTime,
  UniqueTokenId,
  AuthType,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;