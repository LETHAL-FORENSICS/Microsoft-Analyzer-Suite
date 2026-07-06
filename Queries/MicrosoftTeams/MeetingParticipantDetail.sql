-- Title: MeetingParticipantDetail
-- Description: Added information about meeting participants
-- Id: 8ff4f650-baf9-4655-bab9-c6edf9ec1788
-- Author: Martin Willing
-- Date: 2026-07-03
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
  json_extract_string(auditData, '$.MeetingDetailId') AS MeetingDetailId,
  COUNT(*) OVER(PARTITION BY auditData.MeetingDetailId) AS "Count",
  CAST(json_extract_string(auditData, '$.JoinTime') AS TIMESTAMP) AS JoinTime,
  CAST(json_extract_string(auditData, '$.LeaveTime') AS TIMESTAMP) AS LeaveTime,
  LeaveTime - JoinTime AS Duration,
  json_extract_string(auditData, '$.ItemName') AS ItemName,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'UserAgent'), 1).Value AS UserAgent,
  json_extract_string(auditData, '$.DeviceInformation') AS DeviceInformation,
  -- Attendees
  unnest(auditData -> 'Attendees' ->> '$[*].OrganizationId') AS Attendee_OrganizationId,
  unnest(auditData -> 'Attendees' ->> '$[*].RecipientType') AS Attendee_RecipientType,
  unnest(auditData -> 'Attendees' ->> '$[*].UserObjectId') AS Attendee_UserObjectId,
  unnest(auditData -> 'Attendees' ->> '$[*].DisplayName') AS Attendee_DisplayName,
  unnest(auditData -> 'Attendees' ->> '$[*].Role') AS Attendee_Role,
  unnest(auditData -> 'Attendees' ->> '$[*].UPN') AS Attendee_UPN,
  -- InviterInfo  
  unnest(auditData.Attendees).InviterInfo.InviteTime AS InviterInfo_InviteTime,
  unnest(auditData.Attendees).InviterInfo.OrganizationId AS InviterInfo_OrganizationId,
  unnest(auditData.Attendees).InviterInfo.UserType AS InviterInfo_UserType,
  unnest(auditData.Attendees).InviterInfo.DisplayName AS InviterInfo_DisplayName,
  unnest(auditData.Attendees).InviterInfo.UPN AS InviterInfo_UPN,
  unnest(auditData.Attendees).InviterInfo.UserIdentifier AS InviterInfo_UserIdentifier,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'MeetingParticipantDetail'
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
  MeetingDetailId,
  Count,
  JoinTime,
  LeaveTime,
  Duration,
  ItemName,
  UserAgent,
  DeviceInformation,
  Attendee_OrganizationId,
  Attendee_RecipientType,
  Attendee_UserObjectId,
  Attendee_DisplayName
  Attendee_Role,
  Attendee_UPN,
  InviterInfo_InviteTime,
  InviterInfo_OrganizationId,
  InviterInfo_UserType,
  InviterInfo_DisplayName,
  InviterInfo_UPN,
  InviterInfo_UserIdentifier,
  Id
FROM ResultSet
ORDER BY CreationTime DESC;