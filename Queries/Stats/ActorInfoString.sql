-- Title: ActorInfoString (Stats)
-- Description: Creates a statistical breakdown of ActorInfoString field
-- Id: 69962052-4376-4d5b-9829-cb8c0c5d9c55
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    json_extract_string(auditData, '$.ActorInfoString') AS ActorInfoString,
    COUNT(*) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'UAL'
WHERE ActorInfoString IS NOT NULL
GROUP BY ActorInfoString
ORDER BY Count DESC;