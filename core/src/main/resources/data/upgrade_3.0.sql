TRUNCATE TABLE vulnerability;
TRUNCATE TABLE reference;
TRUNCATE TABLE cpeEntry;
TRUNCATE TABLE software;

ALTER TABLE vulnerability ALTER COLUMN cvssScore TO cvssV2Score;
ALTER TABLE vulnerability ALTER COLUMN cvssAccessVector TO cvssV2AccessVector;
ALTER TABLE vulnerability ALTER COLUMN cvssAccessComplexity TO cvssV2AccessComplexity;
ALTER TABLE vulnerability ALTER COLUMN cvssAuthentication TO cvssV2Authentication;
ALTER TABLE vulnerability ALTER COLUMN cvssConfidentialityImpact TO cvssV2ConfidentialityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssIntegrityImpact TO cvssV2IntegrityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssAvailabilityImpact TO cvssV2AvailabilityImpact;
ALTER TABLE vulnerability DROP  COLUMN cwe;
ALTER TABLE vulnerability ADD   COLUMN cvssV2Severity VARCHAR(20), cvssV3AttackVector VARCHAR(20), cvssV3AttackComplexity VARCHAR(20), cvssV3PrivilegesRequired VARCHAR(20), cvssV3UserInteraction VARCHAR(20), cvssV3Scope VARCHAR(20), cvssV3ConfidentialityImpact VARCHAR(20), cvssV3IntegrityImpact VARCHAR(20), cvssV3AvailabilityImpact VARCHAR(20), cvssV3BaseScore DECIMAL(3,1), cvssV3BaseSeverity VARCHAR(20);


CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(10));
CREATE INDEX idxCwe ON cweEntr(cveid);

ALTER TABLE cpeEntry ALTER COLUMN cpe VARCHAR(500);

ALTER TABLE software DROP COLUMN previous;
ALTER TABLE software ADD COLUMN VersionEndExcluding VARCHAR(20), versionEndIncluding VARCHAR(20), versionStartExcluding VARCHAR(20), versionStartIncluding VARCHAR(20), vulnerable BOOLEAN;


ALTER TABLE vulnerability DROP  COLUMN cwe;



DELETE FROM properties WHERE ID like 'NVD CVE%'
UPDATE Properties SET value='4.0' WHERE ID='version';