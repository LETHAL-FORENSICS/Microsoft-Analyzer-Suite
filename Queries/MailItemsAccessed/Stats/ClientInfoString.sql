-- Title: ClientInfoString (Stats)
-- Description: Creates a statistical breakdown of ClientInfoString property
-- Id: 9437d8e6-164b-4512-a370-420253a2e514
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    ClientInfoString,
    COUNT(ClientInfoString) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'MailItemsAccessed'
WHERE ClientInfoString != 'NULL'
GROUP BY ClientInfoString
ORDER BY Count DESC;