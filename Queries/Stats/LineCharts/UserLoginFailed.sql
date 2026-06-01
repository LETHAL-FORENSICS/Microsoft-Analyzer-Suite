-- Title: UserLoginFailed (Line Chart)
-- Description: Creates a line chart of UserLoginFailed property events per day in Excel
-- Id: 417a8503-12f7-47c9-b7f8-d7d4e6333c6d
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    CAST(CreationTime AS DATE) AS CreationTime,
    COUNT(Operation) AS Count
FROM 'Hunt'
WHERE Operation == 'UserLoginFailed'
GROUP BY ALL
ORDER BY CreationTime;