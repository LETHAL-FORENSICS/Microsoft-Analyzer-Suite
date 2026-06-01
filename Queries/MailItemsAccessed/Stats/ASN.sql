-- Title: ASN (Stats)
-- Description: Creates a statistical breakdown of ASN property
-- Id: 617b0e49-bed6-4cb1-8761-f07c3e054d8f
-- Author: Martin Willing
-- Date: 2026-05-31
SELECT
    ASN,
    OrgName,
    COUNT(ASN) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'MailItemsAccessed'
WHERE ASN != 'NULL'
GROUP BY ASN, OrgName
ORDER BY Count DESC;