-- Title: Hunt View --> No IP Enrichment
-- Description: Creates a view and breakdown of all relevant events to analyze suspicious sign-in activity
-- Id: 5cbdefaf-2462-4e03-8598-865c04b9c149
-- Author: Martin Willing
-- Date: 2026-06-06
INSTALL inet;
LOAD inet;
WITH ResultSet AS (
  SELECT 
    CAST(createdDateTime AS TIMESTAMP) AS CreationTime,
    userDisplayName AS UserDisplayName,
    userPrincipalName AS UserPrincipalName,
    userId AS UserId,
    appDisplayName AS AppDisplayName,
    appId AS AppId,
    clientAppUsed AS ClientAppUsed,
    authenticationRequirement AS AuthenticationRequirement,
    signInEventTypes[1] AS SignInEventType,
    authenticationMethodsUsed[1] AS AuthenticationMethodsUsed,
    json_extract_string(status, '$.errorCode') AS ErrorCode,
    json_extract_string(status, '$.failureReason') AS FailureReason,
    json_extract_string(status, '$.additionalDetails') AS AdditionalDetails,
    ipAddress AS ClientIP,
    CASE 
      -- When IPv6 with square brackets and port number --> Remove square brackets and port number
      WHEN ipAddress LIKE '[%]:%' THEN regexp_extract(ipAddress, '\[(.*)\]', 1)
      -- When IPv4 with port number --> Remove port number
      WHEN ipAddress LIKE '%.%.%.%:%' THEN regexp_replace(ipAddress, ':\d+$', '')
      -- When IPv4-mapped IPv6 address --> Remove prefix "^::ffff:"
      WHEN ipAddress LIKE '::ffff:%' THEN regexp_extract(ipAddress, '^::ffff:(.+)$', 1)
      ELSE ipAddress
    END AS IPAddress,
    autonomousSystemNumber AS ASN,
    json_extract_string(location, '$.city') AS City,
    json_extract_string(location, '$.state') AS State,
    json_extract_string(location, '$.countryOrRegion') AS CountryOrRegion,
    ipAddressFromResourceProvider AS IPAddressFromResourceProvider,
    userAgent AS UserAgent,
    sessionId AS SessionId,
    uniqueTokenIdentifier AS UniqueTokenIdentifier,
    incomingTokenType AS IncomingTokenType,
    authenticationProtocol AS authenticationProtocol,
    originalTransferMethod AS OriginalTransferMethod,
    riskDetail AS RiskDetail,
    riskLevelAggregated AS RiskLevelAggregated,
    riskLevelDuringSignIn AS RiskLevelDuringSignIn,
    riskState AS RiskState,
    NULLIF(array_to_string((riskEventTypes_v2)::VARCHAR[], ', '), '') AS RiskEventTypes_v2,
    json_extract_string(deviceDetail, '$.deviceId') AS DeviceId,
    json_extract_string(deviceDetail, '$.displayName') AS DeviceName,
    json_extract_string(deviceDetail, '$.operatingSystem')AS OperatingSystem,
    json_extract_string(deviceDetail, '$.browser')AS Browser,
    json_extract_string(deviceDetail, '$.isCompliant')AS IsCompliant,
    json_extract_string(deviceDetail, '$.isManaged')AS IsManaged,
    json_extract_string(deviceDetail, '$.trustType')AS TrustType,
    REPLACE(userType, 'member', 'Member') AS UserType,
    id AS Id
  FROM 'SignInLogs'
)
SELECT
  CreationTime,
  UserDisplayName,
  UserPrincipalName,
  UserId,
  AppDisplayName,
  AppId,
  ClientAppUsed,
  AuthenticationRequirement,
  SignInEventType,
  AuthenticationMethodsUsed,
  ErrorCode,
  FailureReason,
  AdditionalDetails,
  IPAddress,
  ASN,
  City,
  State,
  CountryOrRegion,
  IPAddressFromResourceProvider,
  UserAgent,
  SessionId,
  UniqueTokenIdentifier,
  IncomingTokenType,
  AuthenticationProtocol,
  OriginalTransferMethod,
  RiskDetail,
  RiskLevelAggregated,
  RiskLevelDuringSignIn,
  RiskState,
  RiskEventTypes_v2,
  DeviceId,
  DeviceName,
  OperatingSystem,
  Browser,
  IsCompliant,
  IsManaged,
  TrustType,
  UserType,
  Id
FROM ResultSet
ORDER BY CreationTime DESC;