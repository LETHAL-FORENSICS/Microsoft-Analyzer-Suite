-- Title: MailItemsAccessed (Line Chart)
-- Description: Creates a line chart of MailItemsAccessed property events per day in Excel
-- Id: b4c28ba4-e09e-447f-b902-90a0a7f119c2
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    CAST(CreationTime AS DATE) AS CreationTime,
    COUNT(Operation) AS Count
FROM 'MailItemsAccessed'
GROUP BY ALL
ORDER BY CreationTime;