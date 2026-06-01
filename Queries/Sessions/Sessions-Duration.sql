-- Title: Sessions Duration
-- Description: Creates an overview of the duration of all sessions
-- Id: 0f6b674a-b6e0-4569-b099-874b77ad21f2
-- Author: Martin Willing
-- Date: 2026-05-16
SELECT 
  SessionId,
  MIN(CreationTime) AS StartDate,
  MAX(CreationTime) AS Enddate,
  date_diff('second', StartDate, EndDate) AS TotalSeconds,
  EndDate - StartDate AS Duration,
  COUNT(*) AS TotalEvents
FROM 'Hunt'
WHERE SessionId != 'NULL'
GROUP BY SessionId
ORDER BY StartDate DESC;