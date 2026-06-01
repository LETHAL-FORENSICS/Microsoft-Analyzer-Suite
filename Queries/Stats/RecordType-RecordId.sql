-- Title: RecordType / RecordId (Stats)
-- Description: Creates a statistical breakdown of RecordType / RecordId properties
-- Id: 5eb5cf46-b81a-473e-a6a2-66e5ead47952
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    RecordType.Id AS RecordId,
    Hunt.RecordType,
    COUNT(*) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
LEFT JOIN RecordType ON (Hunt.RecordType) = RecordType.RecordType
WHERE Hunt.RecordType != 'NULL'
GROUP BY ALL
ORDER BY Count DESC;