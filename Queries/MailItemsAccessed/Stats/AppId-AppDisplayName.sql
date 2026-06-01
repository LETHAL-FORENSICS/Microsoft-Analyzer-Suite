-- Title: AppId / AppDisplayName (Stats)
-- Description: Creates a statistical breakdown of AppId / AppDisplayName properties
-- Id: 4e7826b2-96d0-4460-9bb9-97db162a1302
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    COALESCE(NULLIF(AppId, ''), 'N/A') AS AppId,
    AppDisplayName,
    COUNT(AppId) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'MailItemsAccessed'
WHERE AppId IS NOT NULL 
  AND AppId != 'NULL'
GROUP BY ALL
ORDER BY Count DESC;