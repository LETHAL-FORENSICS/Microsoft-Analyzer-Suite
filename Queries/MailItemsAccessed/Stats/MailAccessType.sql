-- Title: MailAccessType (Stats)
-- Description: Creates a statistical breakdown of MailAccessType property
-- Id: 45a443fc-a541-488d-aa44-8a2fb016622c
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    MailAccessType,
    COUNT(*) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'MailItemsAccessed'
WHERE MailAccessType IS NOT NULL
GROUP BY MailAccessType
ORDER BY Count DESC;