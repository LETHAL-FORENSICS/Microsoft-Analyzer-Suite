-- Title: IPAddress / CountryName (Stats)
-- Description: Creates a statistical breakdown of IPAddress / CountryName properties
-- Id: 79739347-2e21-4d20-b5dd-2c5e5092ada3
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    IPAddress,
    CountryCode,
    CountryName,
    ASN,
    OrgName,
    COUNT(IPAddress) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'MailItemsAccessed'
WHERE IPAddress != 'NULL'
GROUP BY ALL
ORDER BY Count DESC;