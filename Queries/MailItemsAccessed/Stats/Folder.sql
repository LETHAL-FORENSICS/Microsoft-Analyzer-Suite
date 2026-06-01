-- Title: Folder (Stats)
-- Description: Creates a statistical breakdown of Folder property (AffectedItems)
-- Id: 6aa4b1a1-2fe6-4b4e-88ed-e33059559b68
-- Author: Martin Willing
-- Date: 2026-05-31
WITH UnnestedData AS (
  SELECT unnest(string_split(Folder, E'\r\n')) AS SplitFolder
  FROM 'MailItemsAccessed'
  WHERE Folder IS NOT NULL
)
SELECT
    SplitFolder AS Folder,
    COUNT(*) AS Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'UnnestedData'
GROUP BY SplitFolder
ORDER BY Count DESC;