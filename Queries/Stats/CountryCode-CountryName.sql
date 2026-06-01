-- Title: CountryCode / CountryName (Stats)
-- Description: Creates a statistical breakdown of CountryCode and CountryName properties
-- Id: 8e24974b-7fa6-49ac-b4c9-2f4faf9e2383
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    CountryCode,
    CountryName,
    COUNT(CountryCode) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE CountryCode != 'NULL'
GROUP BY CountryCode, CountryName
ORDER BY Count DESC;