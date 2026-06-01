-- Title: IPAddress / CountryName (Stats)
-- Description: Creates a statistical breakdown of IPAddress / CountryName properties
-- Id: 21551e84-69fa-4075-89c1-65ed6892b05d
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    IPAddress,
    CountryCode,
    CountryName,
    ASN,
    OrgName,
    COUNT(IPAddress) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE IPAddress != 'NULL'
GROUP BY ALL
ORDER BY Count DESC;