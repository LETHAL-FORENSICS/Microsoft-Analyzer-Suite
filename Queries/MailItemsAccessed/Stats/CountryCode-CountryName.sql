-- Title: CountryCode / CountryName (Stats)
-- Description: Creates a statistical breakdown of CountryCode and CountryName properties
-- Id: 5fcbafc3-3dd6-40a7-959f-fbc42841505f
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    CountryCode,
    CountryName,
    COUNT(CountryCode) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'MailItemsAccessed'
WHERE CountryCode != 'NULL'
GROUP BY CountryCode, CountryName
ORDER BY Count DESC;