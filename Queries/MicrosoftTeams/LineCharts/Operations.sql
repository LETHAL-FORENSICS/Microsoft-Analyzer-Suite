-- Title: Operations (Line Chart)
-- Description: Creates a line chart of Operation property events per day in Excel
-- Id: fa46deb6-93b6-43f5-abcf-387773578f2a
-- Author: Martin Willing
-- Date: 2026-06-21
SELECT
    CAST(json_extract_string(auditData, '$.CreationTime') AS DATE) AS CreationTime,
    COUNT(Operation) AS Count
FROM 'UAL'
WHERE auditLogRecordType = 'MicrosoftTeams'
GROUP BY ALL
ORDER BY CreationTime;