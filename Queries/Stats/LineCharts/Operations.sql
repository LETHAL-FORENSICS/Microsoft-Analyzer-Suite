-- Title: Operations (Line Chart)
-- Description: Creates a line chart of Operation property events per day in Excel
-- Id: a91fb283-3afd-49b3-ac90-4b04e352a739
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    CAST(CreationTime AS DATE) AS CreationTime,
    COUNT(Operation) AS Count
FROM 'Hunt'
GROUP BY ALL
ORDER BY CreationTime;