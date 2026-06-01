-- Title: Add app role assignment grant to user
-- Description: Detects the addition of an application role assignment grant to a specific user in Microsoft 365. This grants the application permission to access certain resources on behalf of the user.
-- Id: 91726acc-e83a-4cf1-b671-427bfd187413
-- Author: Martin Willing
-- Date: 2026-05-21
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
  json_extract_string(
    (list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.User-Agent'
  ) AS UserAgent,
  json_extract_string(
    (list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.AppId'
  ) AS AppId,
  CASE 
    WHEN NULLIF(trim(json_extract_string((list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.AppId')), '') IS NULL THEN NULL
    WHEN "Application-Blacklist".AppId IS NOT NULL THEN "Application-Blacklist".AppDisplayName
    WHEN MicrosoftApps.AppDisplayName IS NULL THEN 'Third Party Application'
    ELSE MicrosoftApps.AppDisplayName 
  END AS AppDisplayName,
  json_extract_string(auditData, '$.InterSystemsId') AS InterSystemsId,
  json_extract_string(auditData, '$.Id') AS Id,
  json_extract_string(auditData, '$.ModifiedProperties') AS ModifiedProperties,
  json_extract_string(auditData, '$.Actor') AS Actor,
  json_extract_string(auditData, '$.Target') AS Target
FROM 'UAL'
LEFT JOIN MicrosoftApps 
  ON json_extract_string((list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.AppId') = MicrosoftApps.AppId
LEFT JOIN "Application-Blacklist"
  ON json_extract_string((list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.AppId') = "Application-Blacklist".AppId
WHERE Operation = 'Add app role assignment grant to user.'
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
  UserAgent,
  AppId,
  AppDisplayName,
  InterSystemsId,
  Id,
  ModifiedProperties,
  Actor,
  Target
FROM 'ResultSet'
ORDER BY CreationTime DESC;