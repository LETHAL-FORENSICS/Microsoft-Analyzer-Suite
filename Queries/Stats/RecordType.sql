-- Title: RecordType (Stats)
-- Description: Creates a statistical breakdown of RecordType property
-- Id: 4d0a3745-2557-4da7-baa0-484658c053bc
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    RecordType,
    COUNT(RecordType) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE RecordType != 'NULL'
GROUP BY RecordType
ORDER BY Count DESC;