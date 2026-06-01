-- Title: Consent to application
-- Description: Detects when a user grants permissions to an Entra-registered application or when an administrator grants tenant-wide permissions to an application. 
-- Id: c814994a-f79c-4ec2-a859-63938fd82bf2
-- Author: Martin Willing
-- Date: 20255-055-21
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
(list_filter(
  json_transform(auditData, '{"ModifiedProperties": [{"Name": "VARCHAR", "NewValue": "VARCHAR"}]}').ModifiedProperties,
  lambda x: x.Name = 'ConsentContext.IsAdminConsent'
))[1].NewValue AS IsAdminConsent,
(list_filter(
  json_transform(auditData, '{"ModifiedProperties": [{"Name": "VARCHAR", "NewValue": "VARCHAR"}]}').ModifiedProperties,
  lambda x: x.Name = 'ConsentContext.IsAppOnly'
))[1].NewValue AS IsAppOnly,
(list_filter(
  json_transform(auditData, '{"ModifiedProperties": [{"Name": "VARCHAR", "NewValue": "VARCHAR"}]}').ModifiedProperties,
  lambda x: x.Name = 'ConsentContext.OnBehalfOfAll'
))[1].NewValue AS OnBehalfOfAll,
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
WHERE Operation = 'Consent to application.'
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
  IsAdminConsent,
  IsAppOnly,
  OnBehalfOfAll,
  InterSystemsId,
  Id,
  ModifiedProperties,
  Actor,
  Target
FROM 'ResultSet'
ORDER BY CreationTime DESC;