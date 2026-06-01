-- Title: AppId / AppDisplayName (Stats)
-- Description: Creates a statistical breakdown of AppId / AppDisplayName properties
-- Id: 10563f2d-11b4-4389-97aa-b57eb83ab512
-- Author: Martin Willing
-- Date: 2026-05-18
SELECT
    COALESCE(NULLIF(AppId, ''), 'N/A') AS AppId,
    AppDisplayName,
    COUNT(AppId) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE AppId IS NOT NULL 
  AND AppId != 'NULL'
GROUP BY ALL
ORDER BY Count DESC;