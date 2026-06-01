-- Title: Add service principal
-- Description: An application was registered in Entra ID. An application is represented by a service principal in the directory.
-- Id: afb495fc-d865-43ea-a435-099b6157f8a0
-- Author: Martin Willing
-- Date: 2026-05-20
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
  json_extract_string(
    (list_filter(auditData.ExtendedProperties, lambda x: x.name = 'additionalDetails'))[1].Value, '$.AppOwnerOrganizationId'
  ) AS AppOwnerOrganizationId,
  json_extract_string(
    CAST(
      json_transform(
        json_extract(auditData, '$.ModifiedProperties'), 
        '["STRUCT(Name VARCHAR, NewValue VARCHAR)"]'
      ) AS STRUCT(Name VARCHAR, NewValue VARCHAR)[]
    ).filter(lambda x: x.Name = 'DisplayName')[1].NewValue::JSON, 
    '$[0]'
  ) AS AppDisplayName,
  json_extract_string(auditData, '$.InterSystemsId') AS InterSystemsId,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'Add service principal.'
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
  AppDisplayName,
  AppId,
  AppOwnerOrganizationId,
  UserAgent,
  InterSystemsId,
  Id
FROM 'ResultSet'
ORDER BY CreationTime DESC;