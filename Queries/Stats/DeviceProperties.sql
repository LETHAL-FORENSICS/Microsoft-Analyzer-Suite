-- Title: DeviceProperties (Stats)
-- Description: Creates a statistical breakdown of DeviceProperties
-- Id: fd15ae4d-9aa3-426d-bc43-f9289d26b58e
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    DeviceName,
    DeviceId,
    COUNT(DeviceId) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE DeviceId != 'NULL'
GROUP BY DeviceName, DeviceId
ORDER BY Count DESC;