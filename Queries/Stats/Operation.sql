-- Title: Operation (Stats)
-- Description: Creates a statistical breakdown of Operation property
-- Id: eed4f704-bc07-45f1-99f1-0565059afbb3
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    Operation,
    COUNT(Operation) AS Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE Operation != 'NULL'
GROUP BY Operation
ORDER BY Count DESC;