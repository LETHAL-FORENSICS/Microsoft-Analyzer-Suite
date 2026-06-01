-- Title: UserLoggedIn View
-- Description: Creates a view and breakdown of UserLoggedIn events to analyze successful authentication
-- Id: 565aad85-c254-4b4a-b711-ccac0463e173
-- Author: Martin Willing
-- Date: 2026-05-17
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
ORDER BY CreationTime DESC
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
  IPinfo_Lite.country_code AS CountryCode,
  IPinfo_Lite.country AS CountryName,
  IPinfo_Lite.asn AS ASN,
  IPinfo_Lite.as_name AS OrgName,
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
FROM ResultSet
LEFT JOIN IPinfo_Lite
  ON IPAddress::INET <<= IPinfo_Lite.cidr;