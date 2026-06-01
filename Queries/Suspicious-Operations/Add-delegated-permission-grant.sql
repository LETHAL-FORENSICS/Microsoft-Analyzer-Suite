-- Title: Add delegated permission grant
-- Description: A delegated permission grant is created for the permissions needed by the application on behalf of the user.
-- Id: a4f9c642-f575-4237-9ac4-164c12e5080d
-- Author: Martin Willing
-- Date: 2026-05-30
WITH ResultSet AS (
SELECT 
CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  json_extract_string(auditData, '$.Workload') AS Workload,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.ResultStatus') AS ResultStatus,
  json_extract_string(auditData, '$.ObjectId') AS ObjectId,
  json_extract_string(
    (list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.User-Agent'
  ) AS UserAgent,
  json_extract_string(
    (list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.AppId'
  ) AS AppId,
  json_extract_string(
    (list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.ServicePrincipalProvisioningType'
  ) AS ServicePrincipalProvisioningType,
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
WHERE Operation = 'Add delegated permission grant.'
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
  ServicePrincipalProvisioningType,
  InterSystemsId,
  Id,
  ModifiedProperties,
  Actor,
  Target
FROM 'ResultSet'
ORDER BY CreationTime DESC;