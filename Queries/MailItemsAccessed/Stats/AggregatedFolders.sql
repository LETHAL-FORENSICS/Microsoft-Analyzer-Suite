-- Title: AggregatedFolders (Stats)
-- Description: Creates a statistical breakdown of Folder property (AffectedItems)
-- Id: ed75ef59-eb00-4644-b6eb-3d38d26069f8
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    Folder,
    COUNT(*) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'MailItemsAccessed'
WHERE Folder IS NOT NULL
GROUP BY Folder
ORDER BY Count DESC;