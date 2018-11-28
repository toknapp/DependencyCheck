DROP TABLE IF EXISTS software;
DROP TABLE IF EXISTS cpeEntry;
DROP TABLE IF EXISTS reference;
DROP TABLE IF EXISTS vulnerability;
DROP TABLE IF EXISTS properties;
DROP TABLE IF EXISTS cweEntry;

CREATE TABLE vulnerability (id int auto_increment PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), cvssV2Score DECIMAL(3,1), cvssV2AccessVector VARCHAR(20),
	cvssV2AccessComplexity VARCHAR(20), cvssV2Authentication VARCHAR(20), cvssV2ConfidentialityImpact VARCHAR(20),
	cvssV2IntegrityImpact VARCHAR(20), cvssV2AvailabilityImpact VARCHAR(20), cvssV2Severity VARCHAR(20),
        cvssV3AttackVector VARCHAR(20), cvssV3AttackComplexity VARCHAR(20), cvssV3PrivilegesRequired VARCHAR(20),
        cvssV3UserInteraction VARCHAR(20), cvssV3Scope VARCHAR(20), cvssV3ConfidentialityImpact VARCHAR(20),
        cvssV3IntegrityImpact VARCHAR(20), cvssV3AvailabilityImpact VARCHAR(20), cvssV3BaseScore DECIMAL(3,1), 
        cvssV3BaseSeverity VARCHAR(20));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
	CONSTRAINT fkReference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT auto_increment PRIMARY KEY, cpe VARCHAR(500), vendor VARCHAR(255), product VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, VersionEndExcluding VARCHAR(20), versionEndIncluding VARCHAR(20), 
                       versionStartExcluding VARCHAR(20), versionStartIncluding VARCHAR(20), vulnerable BOOLEAN
    , CONSTRAINT fkSoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT fkSoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(10));
CREATE INDEX idxCwe ON cweEntr(cveid);

CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(cpe);
CREATE INDEX idxCpeEntry ON cpeEntry(vendor, product);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));
INSERT INTO properties(id, value) VALUES ('version', '4.0');