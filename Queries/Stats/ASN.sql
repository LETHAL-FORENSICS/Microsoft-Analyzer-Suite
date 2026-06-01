-- Title: ASN (Stats)
-- Description: Creates a statistical breakdown of ASN property
-- Id: 40c5c641-2422-42b5-9bd2-405097b576ef
-- Author: Martin Willing
-- Date: 2026-05-15
SELECT
    ASN,
    OrgName,
    COUNT(ASN) as Count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) AS PercentUse
FROM 'Hunt'
WHERE ASN != 'NULL'
GROUP BY ASN, OrgName
ORDER BY Count DESC;