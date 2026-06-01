-- Title: HygieneTenantEvents
-- Description: Indicates that an automated mail protection mechanism by Exchange Online Protection (EOP) or Microsoft Defender for Office 365 has triggered (e.g. Outbound Spam).
-- Id: f1bf6db9-a7fc-470c-8967-272d39cd710d
-- Author: Martin Willing
-- Date: 2026-05-22
WITH ResultSet AS (
SELECT 
CAST(json_extract_string(auditData, '$.CreationTime') AS TIMESTAMP) AS CreationTime,
  json_extract_string(auditData, '$.UserId') AS UserPrincipalName,
  userType AS UserType,
  json_extract_string(auditData, '$.Workload') AS Workload,
  auditLogRecordType AS RecordType,
  operation AS Operation,
  json_extract_string(auditData, '$.ResultStatus') AS ResultStatus,
  json_extract_string(auditData, '$.Audit') AS Audit,
  json_extract_string(auditData, '$.Event') AS Event,
  json_extract_string(auditData, '$.EventId') AS EventId,
  json_extract_string(auditData, '$.EventValue') AS EventValue,
  json_extract_string(auditData, '$.Reason') AS Reason, -- Contains a specific text string that explains why the email system blocked or restricted a user account
  CAST(regexp_extract(Reason, 'OutboundSpamLast24Hours=(\d+)', 1) AS INTEGER) AS OutboundSpamLast24Hours, -- The total count of all outbound emails sent by the specific user account over the trailing 24 hours.
  CAST(regexp_extract(Reason, 'OutboundMailLast24Hours=(\d+)', 1) AS INTEGER) AS OutboundMailLast24Hours, -- The total number of those outbound emails flagged as spam, phishing, or malicious by Exchange Online Protection (EOP).
  regexp_extract(Reason, 'Last Spam Message MessagetraceId:([a-f0-9\-]+)', 1) AS LastSpamMessageMessageTraceId, -- The GUID assigned to the very last malicious email sent before the account was restricted.
  regexp_extract(Reason, 'CIP=([0-9\.]+)', 1) AS ClientIP,
  CAST(regexp_extract(Reason, 'AS:(\d+)', 1) AS INTEGER) AS AntiSpam,
  Id
FROM 'UAL'
WHERE Operation = 'HygieneTenantEvents'
)
SELECT
  CreationTime,
  UserPrincipalName,
  UserType,
  Workload,
  RecordType,
  Operation,
  ResultStatus,
  Audit,
  Event,
  EventId,
  EventValue,
  Reason,
  OutboundSpamLast24Hours,
  OutboundMailLast24Hours,
  LastSpamMessageMessageTraceId,
  AntiSpam,
  ClientIP,
  IPinfo_Lite.country_code AS CountryCode,
  IPinfo_Lite.country AS CountryName,
  IPinfo_Lite.asn AS ASN,
  IPinfo_Lite.as_name AS OrgName,
  Id
FROM 'ResultSet'
LEFT JOIN IPinfo_Lite
  ON ClientIP::INET <<= IPinfo_Lite.cidr
ORDER BY CreationTime DESC;