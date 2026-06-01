-- Title: Suspicious Sessions
-- Description: Creates an overview of potential hijacked sessions (AitM)
-- Id: 0ef4f2de-a7d0-4929-bfeb-aaa1b28cf61f
-- Author: Martin Willing
-- Date: 2026-05-16
SELECT 
  SessionId,
  COUNT(DISTINCT IPAddress) AS IPAddress,
  COUNT(DISTINCT CountryName) AS Country,
  COUNT(DISTINCT ASN) AS ASN,
  COUNT(DISTINCT OS) AS OS,
  COUNT(DISTINCT BrowserType) FILTER (WHERE BrowserType IS NOT NULL AND BrowserType != 'NULL') AS BrowserType,
  COUNT(DISTINCT UserAgent) FILTER (WHERE UserAgent IS NOT NULL AND UserAgent != 'NULL') AS UserAgent,
  COUNT(DISTINCT ClientInfoString) FILTER (WHERE ClientInfoString IS NOT NULL AND ClientInfoString != 'NULL') AS ClientInfoString,
  COUNT(DISTINCT DeviceId) FILTER (WHERE DeviceId IS NOT NULL AND DeviceId != 'NULL') AS Devices,
  COUNT(*) FILTER (WHERE Operation = 'UserLoggedIn') AS UserLoggedIn,
  COUNT(DISTINCT UniqueTokenId) FILTER (WHERE UniqueTokenId IS NOT NULL AND UniqueTokenId != 'NULL') AS UniqueTokenId,
FROM 'Hunt'
WHERE SessionId != 'NULL'
  AND (
    ObjectId = '4765445b-32c6-49b0-83e6-1d93765276ca' -- OfficeHome
    OR ObjectId = '72782ba9-4490-4f03-8d82-562370ea3566' -- Office365
    OR ObjectId = '00000002-0000-0ff1-ce00-000000000000' -- Office 365 Exchange Online
  )
GROUP BY SessionId
ORDER BY SessionId;