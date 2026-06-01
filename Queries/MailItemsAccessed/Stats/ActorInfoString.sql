-- Title: ActorInfoString (Stats)
-- Description: Creates a statistical breakdown of ActorInfoString property
-- Id: a51a178f-078b-40a5-b6d8-32d537b240b1
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    ActorInfoString,
    COUNT(*) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'MailItemsAccessed'
WHERE ActorInfoString IS NOT NULL
GROUP BY ActorInfoString
ORDER BY Count DESC;