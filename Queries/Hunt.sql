-- Title: Hunt View
-- Description: Creates a view and breakdown of all relevant events to analyze attacker activity
-- Id: 790ab6c0-e903-4844-946d-20cc0a114de4
-- Author: Martin Willing
-- Date: 2026-05-19
INSTALL inet;
LOAD inet;
WITH ResultSet AS (
SELECT 
    list_extract(list_filter(auditData.ExtendedProperties, lambda x: x.Name = 'UserAuthenticationMethod'), 1).Value AS DecimalValue,
    list_aggr(
        [
            item.label FOR item IN [
                {'mask': 1,         'label': 'Password in the Cloud'},
                {'mask': 2,         'label': 'Temporary Access Pass'},
                {'mask': 4,         'label': 'Seamless SSO'},
                {'mask': 8,         'label': 'Pass-through Authentication'},
                {'mask': 16,        'label': 'Password Hash Sync'},
                {'mask': 64,        'label': 'Passwordless Phone Sign-in'},
                {'mask': 256,       'label': 'via Staged Rollout'},
                {'mask': 262144,    'label': 'Windows Hello for Business'},
                {'mask': 524288,    'label': 'QR Code'},
                {'mask': 1048576,   'label': 'SMS Sign-in'},
                {'mask': 2097152,   'label': 'X.509 Certificate'},
                {'mask': 8388608,   'label': 'MacOS Platform Credentials'},
                {'mask': 16777216,  'label': 'QR Code PIN'},
                {'mask': 33554432,  'label': 'Passkey (device-bound)'},
                {'mask': 67108864,  'label': 'Passkey (synced)'},
                {'mask': 134217728, 'label': 'Email Verification Code'}
            ]
            IF (TRY_CAST(DecimalValue AS BIGINT) & item.mask) = item.mask
        ], 
        'string_agg', 
        ', '
    ) AS UserAuthenticationMethod,
  CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  json_extract_string(auditData, '$.Workload') AS Workload,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.ResultStatus') AS ResultStatus,
  objectId AS ObjectId,
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
  list_extract(list_filter(auditData.ExtendedProperties, lambda x: x.Name = 'UserAgent'), 1).Value AS UserAgent,
  json_extract_string(auditData, '$.ClientInfoString') AS ClientInfoString,
  json_extract_string(auditData, '$.ActorInfoString') AS ActorInfoString,
  list_extract(list_filter(auditData.ExtendedProperties, lambda x: x.Name = 'RequestType'), 1).Value AS RequestType,
  list_extract(list_filter(auditData.ExtendedProperties, lambda x: x.Name = 'ResultStatusDetail'), 1).Value AS ResultStatusDetail,
  list_extract(list_filter(auditData.ExtendedProperties, lambda x: x.Name = 'UserAuthenticationMethod'), 1).Value AS UserAuthenticationMethod,
  COALESCE(
    json_extract_string(auditData, '$.SessionId'),
    json_extract_string(auditData, '$.AppAccessContext.AADSessionId'),
    list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'SessionId'), 1).Value,
  ) AS SessionId,
  json_extract_string(auditData, '$.InterSystemsId') AS InterSystemsId,
  COALESCE(
    list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'DeviceId'), 1).Value,
    json_extract_string(auditData, '$.DeviceId')
  ) AS DeviceId, 
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'DeviceName'), 1).Value AS DeviceName,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'OS'), 1).Value AS OS,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'BrowserType'), 1).Value AS BrowserType,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'IsCompliant'), 1).Value AS IsCompliant,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'IsCompliantAndManaged'), 1).Value AS IsCompliantAndManaged,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  json_extract_string(auditData, '$.AuthType') AS AuthType,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
LEFT JOIN MicrosoftApps 
  ON json_extract_string(auditData, '$.AppId') = MicrosoftApps.AppId -- First-Party Applications
LEFT JOIN "Application-Blacklist"
  ON json_extract_string(auditData, '$.AppId') = "Application-Blacklist".AppId -- Blacklisted Applications
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
  IPAddress,
  IPinfo_Lite.country_code AS CountryCode,
  IPinfo_Lite.country AS CountryName,
  IPinfo_Lite.asn AS ASN,
  IPinfo_Lite.as_name AS OrgName,
  UserAgent,
  ClientInfoString,
  ActorInfoString,
  RequestType,
  ResultStatusDetail,
  DecimalValue,
  UserAuthenticationMethod,
  SessionId,
  InterSystemsId,
  DeviceName,
  DeviceId,
  OS,
  BrowserType,
  IsCompliant,
  IsCompliantAndManaged,
  IssuedAtTime,
  UniqueTokenId,
  AuthType,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;