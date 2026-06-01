-- Title: UserLoggedIn (Line Chart)
-- Description: Creates a line chart of UserLoggedIn property events per day in Excel
-- Id: 34f6465f-51f6-4a4c-a466-e0e4629f2355
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    CAST(CreationTime AS DATE) AS CreationTime,
    COUNT(Operation) AS Count
FROM 'Hunt'
WHERE Operation == 'UserLoggedIn'
GROUP BY ALL
ORDER BY CreationTime;