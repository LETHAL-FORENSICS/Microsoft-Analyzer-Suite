-- Title: UserAgent (Stats)
-- Description: Creates a statistical breakdown of UserAgent property
-- Id: a75d2583-da38-4195-99fe-8187453b268d
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT 
    UserAgent,
    COUNT(UserAgent) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE UserAgent != 'NULL'
GROUP BY UserAgent
ORDER BY Count DESC;