-- Title: UserAuthenticationMethod (Stats)
-- Description: Creates a statistical breakdown of UserAuthenticationMethod property
-- Id: a47bee80-7dde-47fb-b75a-37c044d3ae2f
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    DecimalValue,
    UserAuthenticationMethod,
    COUNT(DecimalValue) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE UserAuthenticationMethod != 'NULL'
GROUP BY DecimalValue, UserAuthenticationMethod
ORDER BY Count DESC;