-- Title: RecordType / RecordId / Workload (Stats)
-- Description: Creates a statistical breakdown of RecordType / RecordId / Workload properties
-- Id: 11588b1b-0151-4ee3-9650-3cb84244d600
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    RecordType.Id AS RecordId,
    Hunt.RecordType,
    Hunt.Workload,
    COUNT(*) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
LEFT JOIN RecordType ON (Hunt.RecordType) = RecordType.RecordType
WHERE Hunt.RecordType != 'NULL'
GROUP BY ALL
ORDER BY Count DESC;