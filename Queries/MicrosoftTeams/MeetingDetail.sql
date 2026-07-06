-- Title: MeetingDetail
-- Description: Added details about Teams meeting
-- Id: d343228f-c9e0-4873-affc-544d061b5133
-- Author: Martin Willing
-- Date: 2026-07-04
WITH ResultSet AS (
SELECT 
  CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  organizationId AS OrganizationId,
  userId AS UserId,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  json_extract_string(auditData, '$.Workload') AS Workload,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.ClientIP') AS IPAddress,
  json_extract_string(auditData, '$.ChatThreadId') AS ChatThreadId, 
  json_extract_string(auditData, '$.CommunicationType') AS CommunicationType, 
  json_extract_string(auditData, '$.CommunicationSubType') AS CommunicationSubType, 
  json_extract_string(auditData, '$.ConferenceUri') AS ConferenceUri, 
  json_extract_string(auditData, '$.Modalities') AS Modalities, 
  json_extract_string(auditData, '$.ProviderTypes') AS ProviderTypes, 
  CAST(json_extract_string(auditData, '$.StartTime') AS TIMESTAMP) AS StartTime,
  CAST(json_extract_string(auditData, '$.EndTime') AS TIMESTAMP) AS EndTime,
  EndTime - StartTime AS Duration,
  json_extract_string(auditData, '$.MeetingURL') AS MeetingURL, 
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'UserAgent'), 1).Value AS UserAgent,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'UsersInvitedDuringMeeting'), 1).Value AS UsersInvitedDuringMeeting,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'RTMPInEnabled'), 1).Value AS RTMPInEnabled,
  auditData->'Organizer'->>'UserObjectId' AS Organizer_OrganizationId,
  auditData->'Organizer'->>'UserObjectId' AS Organizer_UserObjectId,
  auditData->'Organizer'->>'RecipientType' AS Organizer_RecipientType,
  CASE auditData->'Organizer'->>'Role'
    WHEN '1' THEN 'Member'
    WHEN '2' THEN 'Owner'
    WHEN '3' THEN 'Guest'
    ELSE 'Unknown'
  END AS Organizer_Role,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'MeetingDetail'
)
SELECT
  CreationTime,
  OrganizationId,
  UserId,
  UserPrincipalName,
  UserType,
  Workload,
  RecordType,
  Operation,
  IPAddress,
  ChatThreadId,
  CommunicationType,
  CommunicationSubType,
  ConferenceUri,
  Modalities,
  ProviderTypes,
  StartTime,
  EndTime,
  Duration,
  MeetingURL,
  UserAgent,
  UsersInvitedDuringMeeting,
  RTMPInEnabled,
  Organizer_OrganizationId,
  Organizer_UserObjectId,
  Organizer_RecipientType,
  Organizer_Role,
  Id
FROM ResultSet
ORDER BY CreationTime DESC;