-- Title: ClientInfoString (Stats)
-- Description: Creates a statistical breakdown of ClientInfoString property
-- Id: 6a88658e-8c96-400d-b69b-4da33cb73b4d
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    ClientInfoString,
    COUNT(ClientInfoString) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE ClientInfoString != 'NULL'
GROUP BY ClientInfoString
ORDER BY Count DESC;