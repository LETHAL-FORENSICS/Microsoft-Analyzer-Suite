-- Title: Find-AiTMSuspiciousUserLogin
-- Description: Identifies consecutive logins from different IP addresses which occur within about 30 seconds of each other. Indicates potential Adversary-in-The-Middle (AiTM) Phishing Attacks [T1557]. 
-- Id: b9773013-8d87-4e92-960a-707a3ddd7927
-- Author: Martin Willing
-- Date: 2026-05-18
INSTALL inet;
LOAD inet;
WITH ResultSet AS (
SELECT
  CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.ResultStatus') AS ResultStatus,
  objectId AS ObjectId,
  json_extract_string(auditData, '$.AppId') AS AppId,
  MicrosoftApps.AppDisplayName AS AppDisplayName,
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
  list_extract(list_filter(auditData.ExtendedProperties, lambda x: x.Name = 'RequestType'), 1).Value AS RequestType,
  list_extract(list_filter(auditData.ExtendedProperties, lambda x: x.Name = 'ResultStatusDetail'), 1).Value AS ResultStatusDetail,
  list_extract(list_filter(auditData.ExtendedProperties, lambda x: x.Name = 'UserAuthenticationMethod'), 1).Value AS UserAuthenticationMethod,
  COALESCE(
    json_extract_string(auditData, '$.SessionId'),
    json_extract_string(auditData, '$.AppAccessContext.AADSessionId'),
    list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'SessionId'), 1).Value,
  ) AS SessionId,
  json_extract_string(auditData, '$.InterSystemsId') AS InterSystemsId,
  json_extract_string(auditData, '$.ErrorNumber') AS ErrorNumber,
  Status.Message AS Message,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'DeviceName'), 1).Value AS DeviceName,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'DeviceId'), 1).Value AS DeviceId,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'OS'), 1).Value AS OS,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'BrowserType'), 1).Value AS BrowserType,
  TrustType.Description AS TrustType,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'IsCompliant'), 1).Value AS IsCompliant,
  list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'IsCompliantAndManaged'), 1).Value AS IsCompliantAndManaged,
  json_extract_string(auditData, '$.AppAccessContext.IssuedAtTime') AS IssuedAtTime,
  json_extract_string(auditData, '$.AppAccessContext.UniqueTokenId') AS UniqueTokenId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
LEFT JOIN MicrosoftApps ON (json_extract_string(auditData, '$.AppId')) = MicrosoftApps.AppId
LEFT JOIN Status ON (json_extract_string(auditData, '$.ErrorNumber')) = Status.ErrorCode
LEFT JOIN TrustType ON (list_extract(list_filter(auditData.DeviceProperties, lambda x: x.Name = 'TrustType'), 1).Value) = TrustType.Value
WHERE Operation = 'UserLoggedIn'
),
IPinfo_Lite AS (
  SELECT
    ResultSet.*,
    IPinfo_Lite.country_code AS CountryCode,
    IPinfo_Lite.country AS CountryName,
    IPinfo_Lite.asn AS ASN,
    IPinfo_Lite.as_name AS OrgName
  FROM ResultSet
  LEFT JOIN IPinfo_Lite
    ON ResultSet.IPAddress::INET <<= IPinfo_Lite.cidr
),
TimeSpan AS (
  SELECT *,
    LAG(IPAddress) OVER (PARTITION BY UserPrincipalName ORDER BY CreationTime) AS PrevIP,
    LAG(CreationTime) OVER (PARTITION BY UserPrincipalName ORDER BY CreationTime) AS PrevTime,
    LEAD(IPAddress) OVER (PARTITION BY UserPrincipalName ORDER BY CreationTime) AS NextIP,
    LEAD(CreationTime) OVER (PARTITION BY UserPrincipalName ORDER BY CreationTime) AS NextTime
  FROM IPinfo_Lite
)
SELECT 
  CreationTime,
  UserPrincipalName,
  UserType,
  RecordType,
  Operation,
  ResultStatus,
  ObjectId,
  AppId,
  AppDisplayName,
  IPAddress,
  CountryCode,
  CountryName,
  ASN,
  OrgName,
  UserAgent,
  RequestType,
  ResultStatusDetail,
  UserAuthenticationMethod,
  SessionId,
  InterSystemsId,
  ErrorNumber,
  Message,
  DeviceName,
  DeviceId,
  OS,
  BrowserType,
  TrustType,
  IsCompliant,
  IsCompliantAndManaged,
  IssuedAtTime,
  UniqueTokenId,
  Id
FROM TimeSpan
WHERE 
  ((IPAddress != PrevIP) AND (CreationTime - PrevTime <= INTERVAL 30 SECOND))
  OR 
  ((IPAddress != NextIP) AND (NextTime - CreationTime <= INTERVAL 30 SECOND))
ORDER BY CreationTime DESC;

-- Step 1: User enters credentials on the phishing page.
-- Step 2: AiTM server relays credentials to the Microsoft server and authenticates.
-- Step 3: User is redirected to the Microsoft portal or a fake landing page.

-- In the Unified Audit Logs (UAL), steps 2 and 3 are recorded as consecutive logins from different IPs which occur within about 30 seconds of each other—and often within only a couple of seconds. 
-- The first login will be the AiTM server (Step 2), with the second login being from the user’s legitimate IP address (Step 3).

-- Note: The adversary may occasionally require more time to copy the session token from the AiTM server to a different machine.

-- Check for known misused ObjectIds: 
-- 4765445b-32c6-49b0-83e6-1d93765276ca OfficeHome
-- 72782ba9-4490-4f03-8d82-562370ea3566 Office365
-- 00000002-0000-0ff1-ce00-000000000000 Office 365 Exchange Online

-- TODO
-- Use the faster JSON extraction operator ->> instead of json_extract_string

-- Old Approach: SELECT json_extract_string(metadata, '$.user.id') FROM table;
-- New Approach: SELECT metadata->>'$.user.id' FROM table