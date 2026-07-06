-- Title: CallParticipantDetail
-- Description: Added information about call participants
-- Id: 80272c85-91c8-4fcf-9cd8-d8533c7d0cdf
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
  json_extract_string(auditData, '$.CallId') AS CallId, 
  COUNT(*) OVER(PARTITION BY auditData.CallId) AS "Count",
  CAST(json_extract_string(auditData, '$.JoinTime') AS TIMESTAMP) AS JoinTime,
  CAST(json_extract_string(auditData, '$.LeaveTime') AS TIMESTAMP) AS LeaveTime,
  LeaveTime - JoinTime AS Duration,
  json_extract_string(auditData, '$.ItemName') AS ItemName,
  list_extract(list_filter(auditData.ExtraProperties, lambda x: x.Key = 'UserAgent'), 1).Value AS UserAgent,
  json_extract_string(auditData, '$.DeviceId') AS DeviceId,
  json_extract_string(auditData, '$.DeviceInformation') AS DeviceInformation,
  -- Attendees
  unnest(auditData -> 'Attendees' ->> '$[*].ProviderType') AS Attendee_ProviderType,
  unnest(auditData -> 'Attendees' ->> '$[*].RecipientType') AS Attendee_RecipientType,
  unnest(auditData -> 'Attendees' ->> '$[*].UserObjectId') AS Attendee_UserObjectId,
  unnest(auditData -> 'Attendees' ->> '$[*].DisplayName') AS Attendee_DisplayName,
  unnest(auditData -> 'Attendees' ->> '$[*].Role') AS Attendee_Role,
  unnest(auditData -> 'Attendees' ->> '$[*].UPN') AS Attendee_UPN,
  unnest(auditData -> 'Attendees' ->> '$[*].IsAADGuest') AS Attendee_IsAADGuest,
  unnest(auditData -> 'Attendees' ->> '$[*].IsOrganizer') AS Attendee_IsOrganizer,
  unnest(auditData -> 'Attendees' ->> '$[*].OrganizationId') AS Attendee_OrganizationId,
  -- ParticipantInfo
  NULLIF(array_to_string(CAST(auditData->'ParticipantInfo'->'ParticipatingTenantIds' AS VARCHAR[]), ', '), '') AS ParticipatingTenantIds, 
  -- ArtifactsShared
  unnest(json_transform(auditData -> '$.ArtifactsShared[*].ArtifactSharedName', '["VARCHAR"]')) AS ArtifactSharedName,
  unnest(auditData->>'$.ArtifactsShared[*].ArtifactShareSessions[*].ScreenShareId') AS ScreenShareId,
  unnest(auditData->>'$.ArtifactsShared[*].ArtifactShareSessions[*].StartTimestamp') AS StartTimestamp,
  unnest(auditData->>'$.ArtifactsShared[*].ArtifactShareSessions[*].EndTimestamp') AS EndTimestamp,
  -- ScreenShareControl
  unnest(json_transform(auditData -> '$.ScreenShareControl[*].ControlStartTimestamp', '["VARCHAR"]')) AS ControlStartTimestamp,
  unnest(json_transform(auditData -> '$.ScreenShareControl[*].ControlEndTimestamp', '["VARCHAR"]')) AS ControlEndTimestamp,
  unnest(json_transform(auditData -> '$.ScreenShareControl[*].ControlRecipientUserId', '["VARCHAR"]')) AS ControlRecipientUserId,
  list_extract(list_filter(unnest(auditData.ScreenShareControl).Events, lambda x: x.Status = 'ControlRequest'), 1).Time AS ControlRequest,
  list_extract(list_filter(unnest(auditData.ScreenShareControl).Events, lambda x: x.Status = 'ControlRequestAccepted'), 1).Time AS ControlRequestAccepted,
  list_extract(list_filter(unnest(auditData.ScreenShareControl).Events, lambda x: x.Status = 'ControlStarted'), 1).Time AS ControlStarted,
  list_extract(list_filter(unnest(auditData.ScreenShareControl).Events, lambda x: x.Status = 'ControlTerminated'), 1).Time AS ControlTerminated,
  ControlTerminated - ControlStarted AS ControlDuration,
  json_extract_string(auditData, '$.Id') AS Id
FROM 'UAL'
WHERE Operation = 'CallParticipantDetail'
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
  CallId,
  Count,
  JoinTime,
  LeaveTime,
  Duration,
  ItemName,
  UserAgent,
  DeviceId,
  DeviceInformation,
  Attendee_ProviderType,
  Attendee_RecipientType,
  Attendee_UserObjectId,
  Attendee_DisplayName,
  Attendee_Role,
  Attendee_UPN,
  Attendee_IsAADGuest,
  Attendee_IsOrganizer,
  Attendee_OrganizationId,
  ParticipatingTenantIds,
  ArtifactSharedName,
  ScreenShareId,
  StartTimestamp,
  EndTimestamp,
  ControlStartTimestamp,
  ControlEndTimestamp,
  ControlRecipientUserId,
  ControlRequest,
  ControlRequestAccepted,
  ControlStarted,
  ControlTerminated,
  ControlDuration,
  Id
FROM ResultSet
ORDER BY CreationTime DESC;